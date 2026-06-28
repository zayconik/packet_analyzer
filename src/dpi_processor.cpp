#include "dpi_processor.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <algorithm>

namespace DPI {

namespace {

struct InternalFlow {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
};

uint32_t parseIP(const std::string& ip) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;
    for (char c : ip) {
        if (c == '.') {
            result |= static_cast<uint32_t>(octet << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    return result | static_cast<uint32_t>(octet << shift);
}

std::string formatIP(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

std::string protocolName(uint8_t protocol) {
    if (protocol == 6) return "TCP";
    if (protocol == 17) return "UDP";
    return "?";
}

std::string jsonEscape(const std::string& s) {
    std::ostringstream out;
    for (char c : s) {
        switch (c) {
            case '"':  out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c))
                        << std::dec << std::setfill(' ');
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

class BlockingRules {
public:
    std::unordered_set<uint32_t> blocked_ips;
    std::unordered_set<AppType> blocked_apps;
    std::vector<std::string> blocked_domains;

    void blockIP(const std::string& ip) {
        blocked_ips.insert(parseIP(ip));
    }

    void blockApp(const std::string& app) {
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps.insert(static_cast<AppType>(i));
                return;
            }
        }
    }

    void blockDomain(const std::string& domain) {
        blocked_domains.push_back(domain);
    }

    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        if (blocked_ips.count(src_ip)) return true;
        if (blocked_apps.count(app)) return true;
        for (const auto& dom : blocked_domains) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

    bool isAppBlocked(AppType app) const {
        return blocked_apps.count(app) > 0;
    }
};

} // namespace

DPIProcessor::DPIProcessor() : config_() {}
DPIProcessor::DPIProcessor(const Config& config) : config_(config) {}

std::vector<std::string> DPIProcessor::supportedApps() {
    std::vector<std::string> apps;
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        AppType type = static_cast<AppType>(i);
        if (type == AppType::UNKNOWN || type == AppType::APP_COUNT) continue;
        apps.push_back(appTypeToString(type));
    }
    std::sort(apps.begin(), apps.end());
    return apps;
}

ProcessingResult DPIProcessor::process(const std::string& input_file,
                                         const std::string& output_file) {
    ProcessingResult result;
    result.output_file = output_file;

    BlockingRules rules;
    for (const auto& ip : config_.block_ips) rules.blockIP(ip);
    for (const auto& app : config_.block_apps) rules.blockApp(app);
    for (const auto& dom : config_.block_domains) rules.blockDomain(dom);

    PacketAnalyzer::PcapReader reader;
    reader.setQuiet(config_.quiet);
    if (!reader.open(input_file)) {
        result.error = "Cannot open input file: " + input_file;
        return result;
    }

    std::ofstream output(output_file, std::ios::binary);
    if (!output.is_open()) {
        result.error = "Cannot open output file: " + output_file;
        return result;
    }

    const auto& header = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));

    std::unordered_map<FiveTuple, InternalFlow, FiveTupleHash> flows;
    std::unordered_map<AppType, uint64_t> app_stats;

    PacketAnalyzer::RawPacket raw;
    PacketAnalyzer::ParsedPacket parsed;

    while (reader.readNextPacket(raw)) {
        result.total_packets++;

        if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

        FiveTuple tuple;
        tuple.src_ip = parseIP(parsed.src_ip);
        tuple.dst_ip = parseIP(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;

        InternalFlow& flow = flows[tuple];
        if (flow.packets == 0) {
            flow.tuple = tuple;
        }
        flow.packets++;
        flow.bytes += raw.data.size();

        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS) &&
            flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 443) {

            size_t payload_offset = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            payload_offset += ip_ihl * 4;

            if (payload_offset + 12 < raw.data.size()) {
                uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
                payload_offset += tcp_offset * 4;

                if (payload_offset < raw.data.size()) {
                    size_t payload_len = raw.data.size() - payload_offset;
                    if (payload_len > 5) {
                        auto sni = SNIExtractor::extract(
                            raw.data.data() + payload_offset, payload_len);
                        if (sni) {
                            flow.sni = *sni;
                            flow.app_type = sniToAppType(*sni);
                        }
                    }
                }
            }
        }

        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTP) &&
            flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 80) {

            size_t payload_offset = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            payload_offset += ip_ihl * 4;

            if (payload_offset + 12 < raw.data.size()) {
                uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
                payload_offset += tcp_offset * 4;

                if (payload_offset < raw.data.size()) {
                    size_t payload_len = raw.data.size() - payload_offset;
                    auto host = HTTPHostExtractor::extract(
                        raw.data.data() + payload_offset, payload_len);
                    if (host) {
                        flow.sni = *host;
                        flow.app_type = sniToAppType(*host);
                    }
                }
            }
        }

        if (flow.app_type == AppType::UNKNOWN &&
            (parsed.dest_port == 53 || parsed.src_port == 53)) {
            flow.app_type = AppType::DNS;
        }

        if (flow.app_type == AppType::UNKNOWN) {
            if (parsed.dest_port == 443) flow.app_type = AppType::HTTPS;
            else if (parsed.dest_port == 80) flow.app_type = AppType::HTTP;
        }

        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni);
        }

        app_stats[flow.app_type]++;

        if (flow.blocked) {
            result.dropped++;
        } else {
            result.forwarded++;
            PacketAnalyzer::PcapPacketHeader pkt_hdr;
            pkt_hdr.ts_sec = raw.header.ts_sec;
            pkt_hdr.ts_usec = raw.header.ts_usec;
            pkt_hdr.incl_len = static_cast<uint32_t>(raw.data.size());
            pkt_hdr.orig_len = static_cast<uint32_t>(raw.data.size());
            output.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
            output.write(reinterpret_cast<const char*>(raw.data.data()),
                         static_cast<std::streamsize>(raw.data.size()));
        }
    }

    reader.close();
    output.close();

    result.active_flows = flows.size();

    std::vector<std::pair<AppType, uint64_t>> sorted_apps(app_stats.begin(), app_stats.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (const auto& [app, count] : sorted_apps) {
        AppStat stat;
        stat.name = appTypeToString(app);
        stat.count = count;
        stat.percent = result.total_packets > 0
            ? 100.0 * count / result.total_packets
            : 0.0;
        stat.blocked = rules.isAppBlocked(app);
        result.app_breakdown.push_back(stat);
    }

    std::unordered_map<std::string, AppType> unique_snis;
    for (const auto& [tuple, flow] : flows) {
        if (!flow.sni.empty()) {
            unique_snis[flow.sni] = flow.app_type;
        }

        FlowInfo info;
        info.src_ip = formatIP(flow.tuple.src_ip);
        info.dst_ip = formatIP(flow.tuple.dst_ip);
        info.src_port = flow.tuple.src_port;
        info.dst_port = flow.tuple.dst_port;
        info.protocol = protocolName(flow.tuple.protocol);
        info.app = appTypeToString(flow.app_type);
        info.sni = flow.sni;
        info.packets = flow.packets;
        info.bytes = flow.bytes;
        info.blocked = flow.blocked;
        result.flows.push_back(info);
    }

    for (const auto& [sni, app] : unique_snis) {
        DomainInfo domain;
        domain.domain = sni;
        domain.app = appTypeToString(app);
        domain.blocked = rules.isAppBlocked(app);
        for (const auto& blocked_dom : rules.blocked_domains) {
            if (sni.find(blocked_dom) != std::string::npos) {
                domain.blocked = true;
                break;
            }
        }
        result.domains.push_back(domain);
    }

    std::sort(result.domains.begin(), result.domains.end(),
              [](const DomainInfo& a, const DomainInfo& b) {
                  return a.domain < b.domain;
              });

    result.success = true;
    return result;
}

std::string DPIProcessor::toJson(const ProcessingResult& result) const {
    std::ostringstream json;
    json << std::fixed << std::setprecision(1);

    json << "{\n";
    json << "  \"success\": " << (result.success ? "true" : "false") << ",\n";
    json << "  \"error\": \"" << jsonEscape(result.error) << "\",\n";
    json << "  \"total_packets\": " << result.total_packets << ",\n";
    json << "  \"forwarded\": " << result.forwarded << ",\n";
    json << "  \"dropped\": " << result.dropped << ",\n";
    json << "  \"active_flows\": " << result.active_flows << ",\n";
    json << "  \"output_file\": \"" << jsonEscape(result.output_file) << "\",\n";

    json << "  \"app_breakdown\": [\n";
    for (size_t i = 0; i < result.app_breakdown.size(); i++) {
        const auto& app = result.app_breakdown[i];
        json << "    {\"name\": \"" << jsonEscape(app.name) << "\", "
             << "\"count\": " << app.count << ", "
             << "\"percent\": " << app.percent << ", "
             << "\"blocked\": " << (app.blocked ? "true" : "false") << "}";
        if (i + 1 < result.app_breakdown.size()) json << ",";
        json << "\n";
    }
    json << "  ],\n";

    json << "  \"domains\": [\n";
    for (size_t i = 0; i < result.domains.size(); i++) {
        const auto& d = result.domains[i];
        json << "    {\"domain\": \"" << jsonEscape(d.domain) << "\", "
             << "\"app\": \"" << jsonEscape(d.app) << "\", "
             << "\"blocked\": " << (d.blocked ? "true" : "false") << "}";
        if (i + 1 < result.domains.size()) json << ",";
        json << "\n";
    }
    json << "  ],\n";

    json << "  \"flows\": [\n";
    for (size_t i = 0; i < result.flows.size(); i++) {
        const auto& f = result.flows[i];
        json << "    {"
             << "\"src_ip\": \"" << jsonEscape(f.src_ip) << "\", "
             << "\"dst_ip\": \"" << jsonEscape(f.dst_ip) << "\", "
             << "\"src_port\": " << f.src_port << ", "
             << "\"dst_port\": " << f.dst_port << ", "
             << "\"protocol\": \"" << jsonEscape(f.protocol) << "\", "
             << "\"app\": \"" << jsonEscape(f.app) << "\", "
             << "\"sni\": \"" << jsonEscape(f.sni) << "\", "
             << "\"packets\": " << f.packets << ", "
             << "\"bytes\": " << f.bytes << ", "
             << "\"blocked\": " << (f.blocked ? "true" : "false") << "}";
        if (i + 1 < result.flows.size()) json << ",";
        json << "\n";
    }
    json << "  ]\n";

    json << "}\n";
    return json.str();
}

} // namespace DPI
