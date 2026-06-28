#include "dpi_processor.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace DPI;

namespace {

std::vector<std::string> splitCsv(const std::string& value) {
    std::vector<std::string> items;
    std::string current;
    for (char c : value) {
        if (c == ',') {
            if (!current.empty()) items.push_back(current);
            current.clear();
        } else if (c != ' ') {
            current += c;
        }
    }
    if (!current.empty()) items.push_back(current);
    return items;
}

void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " <input.pcap> <output.pcap> [options]\n\n"
              << "Options:\n"
              << "  --block-ip <ip>[,<ip>...]       Block source IPs\n"
              << "  --block-app <app>[,<app>...]    Block applications\n"
              << "  --block-domain <dom>[,<dom>...] Block domains (substring)\n"
              << "  --json                          Print JSON report to stdout\n"
              << "  --list-apps                     List supported app names\n";
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc >= 2 && std::string(argv[1]) == "--list-apps") {
        for (const auto& app : DPIProcessor::supportedApps()) {
            std::cout << app << "\n";
        }
        return 0;
    }

    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];
    bool json_output = false;
    DPIProcessor::Config config;

    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--json") {
            json_output = true;
        } else if (arg == "--block-ip" && i + 1 < argc) {
            auto ips = splitCsv(argv[++i]);
            config.block_ips.insert(config.block_ips.end(), ips.begin(), ips.end());
        } else if (arg == "--block-app" && i + 1 < argc) {
            auto apps = splitCsv(argv[++i]);
            config.block_apps.insert(config.block_apps.end(), apps.begin(), apps.end());
        } else if (arg == "--block-domain" && i + 1 < argc) {
            auto domains = splitCsv(argv[++i]);
            config.block_domains.insert(config.block_domains.end(),
                                        domains.begin(), domains.end());
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        }
    }

    config.quiet = json_output;

    DPIProcessor processor(config);
    ProcessingResult result = processor.process(input_file, output_file);

    if (json_output) {
        std::cout << processor.toJson(result);
    } else if (!result.success) {
        std::cerr << result.error << "\n";
    }

    return result.success ? 0 : 1;
}
