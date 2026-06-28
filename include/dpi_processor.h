#ifndef DPI_PROCESSOR_H
#define DPI_PROCESSOR_H

#include "types.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>

namespace DPI {

struct FlowInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;
    std::string app;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
};

struct AppStat {
    std::string name;
    uint64_t count = 0;
    double percent = 0.0;
    bool blocked = false;
};

struct DomainInfo {
    std::string domain;
    std::string app;
    bool blocked = false;
};

struct ProcessingResult {
    bool success = false;
    std::string error;

    uint64_t total_packets = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;
    uint64_t active_flows = 0;

    std::vector<AppStat> app_breakdown;
    std::vector<DomainInfo> domains;
    std::vector<FlowInfo> flows;

    std::string output_file;
};

class DPIProcessor {
public:
    struct Config {
        std::vector<std::string> block_ips;
        std::vector<std::string> block_apps;
        std::vector<std::string> block_domains;
        bool quiet = false;
    };

    explicit DPIProcessor(const Config& config);
    DPIProcessor();

    ProcessingResult process(const std::string& input_file,
                             const std::string& output_file);

    std::string toJson(const ProcessingResult& result) const;

    static std::vector<std::string> supportedApps();

private:
    Config config_;
};

} // namespace DPI

#endif // DPI_PROCESSOR_H
