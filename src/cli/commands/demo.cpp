#include "../parser.h"
#include "../../demo/demos.h"
#include "../../log/log.h"
#include <iostream>

namespace cli {

int cmd_demo(const GlobalOptions& globals, const std::vector<std::string>& args) {
    (void)globals;
    if (args.empty()) {
        std::cerr << "Usage: kwatch demo <scenario> [OPTIONS]\n"
                  << "Scenarios: syn-flood, ping-flood, udp-storm\n";
        return 64;
    }

    std::string scenario = args[0];
    demo::DemoConfig cfg;
    cfg.override_safety = false;

    // Very basic parsing for demo options
    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--target" && i + 1 < args.size()) cfg.target_ip = args[++i];
        else if (args[i] == "--port" && i + 1 < args.size()) cfg.target_port = (uint16_t)std::stoi(args[++i]);
        else if (args[i] == "--duration" && i + 1 < args.size()) cfg.duration_s = std::stoi(args[++i]);
        else if (args[i] == "--rate" && i + 1 < args.size()) cfg.rate_pps = std::stoi(args[++i]);
        else if (args[i] == "--i-know-what-im-doing") cfg.override_safety = true;
    }

    util::Result<void> res = util::Result<void>::Ok();
    if (scenario == "syn-flood") res = demo::run_syn_flood(cfg);
    else if (scenario == "ping-flood") res = demo::run_ping_flood(cfg);
    else if (scenario == "udp-storm") res = demo::run_udp_storm(cfg);
    else {
        std::cerr << "Unknown scenario: " << scenario << "\n";
        return 64;
    }

    if (!res.is_ok()) {
        std::cerr << "Demo failed: " << res.error() << "\n";
        return 125;
    }

    std::cout << "Demo '" << scenario << "' finished successfully.\n";
    return 0;
}

} // namespace cli