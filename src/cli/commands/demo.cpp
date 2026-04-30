#include "../../demo/demos.h"
#include "../../log/log.h"
#include "../parser.h"
#include <cstdint>
#include <cstdio>
#include <limits>

namespace cli {

static util::Result<uint32_t> parse_u32_option(const std::string &option, const std::string &value,
                                               const std::string &suffix = "") {
    std::string digits = value;
    if (!suffix.empty() && value.size() > suffix.size() &&
        value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0) {
        digits = value.substr(0, value.size() - suffix.size());
    } else if (!suffix.empty()) {
        bool all_digits = !digits.empty();
        for (char ch : digits) {
            if (ch < '0' || ch > '9') {
                all_digits = false;
                break;
            }
        }
        if (!all_digits) {
            return util::Result<uint32_t>::Err("Invalid value for " + option + ": " + value);
        }
    }

    try {
        size_t pos = 0;
        const unsigned long parsed = std::stoul(digits, &pos, 10);
        if (pos != digits.size() || parsed > std::numeric_limits<uint32_t>::max()) {
            return util::Result<uint32_t>::Err("Invalid value for " + option + ": " + value);
        }
        return util::Result<uint32_t>::Ok(static_cast<uint32_t>(parsed));
    } catch (...) {
        return util::Result<uint32_t>::Err("Invalid value for " + option + ": " + value);
    }
}

static util::Result<uint16_t> parse_u16_option(const std::string &option,
                                               const std::string &value) {
    auto parsed = parse_u32_option(option, value);
    if (!parsed.is_ok()) {
        return util::Result<uint16_t>::Err(parsed.error());
    }
    if (parsed.value() > std::numeric_limits<uint16_t>::max()) {
        return util::Result<uint16_t>::Err("Invalid value for " + option + ": " + value);
    }
    return util::Result<uint16_t>::Ok(static_cast<uint16_t>(parsed.value()));
}

static util::Result<void> parse_target_option(const std::string &value, demo::DemoConfig &cfg) {
    const size_t colon = value.rfind(':');
    if (colon == std::string::npos || value.find(':') != colon) {
        cfg.target_ip = value;
        return util::Result<void>::Ok();
    }

    const std::string host = value.substr(0, colon);
    const std::string port = value.substr(colon + 1U);
    if (host.empty() || port.empty()) {
        return util::Result<void>::Err("Invalid value for --target: " + value);
    }

    auto parsed_port = parse_u16_option("--target port", port);
    if (!parsed_port.is_ok()) {
        return util::Result<void>::Err(parsed_port.error());
    }
    cfg.target_ip = host;
    cfg.target_port = parsed_port.value();
    return util::Result<void>::Ok();
}

int cmd_demo(const GlobalOptions &globals, const std::vector<std::string> &args) {
    (void)globals;
    if (args.empty()) {
        std::fputs("Usage: kwatch demo <scenario> [OPTIONS]\n"
                   "Scenarios: syn-flood, ping-flood, udp-storm\n",
                   stderr);
        return 64;
    }

    std::string scenario = args[0];
    demo::DemoConfig cfg;
    cfg.target_ip = "127.0.0.1"; // Default (R5.17)
    cfg.target_port = 80;
    cfg.rate_pps = 100;
    cfg.duration_s = 5;
    cfg.override_safety = false;

    // Very basic parsing for demo options
    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--target") {
            if (i + 1 >= args.size()) {
                LOG_ERROR("demo", "--target requires an argument");
                return 64;
            }
            auto parsed = parse_target_option(args[++i], cfg);
            if (!parsed.is_ok()) {
                LOG_ERROR("demo", parsed.error());
                return 64;
            }
        } else if (args[i] == "--port") {
            if (i + 1 >= args.size()) {
                LOG_ERROR("demo", "--port requires an argument");
                return 64;
            }
            auto parsed = parse_u16_option("--port", args[++i]);
            if (!parsed.is_ok()) {
                LOG_ERROR("demo", parsed.error());
                return 64;
            }
            cfg.target_port = parsed.value();
        } else if (args[i] == "--duration") {
            if (i + 1 >= args.size()) {
                LOG_ERROR("demo", "--duration requires an argument");
                return 64;
            }
            auto parsed = parse_u32_option("--duration", args[++i], "s");
            if (!parsed.is_ok()) {
                LOG_ERROR("demo", parsed.error());
                return 64;
            }
            cfg.duration_s = parsed.value();
        } else if (args[i] == "--rate") {
            if (i + 1 >= args.size()) {
                LOG_ERROR("demo", "--rate requires an argument");
                return 64;
            }
            auto parsed = parse_u32_option("--rate", args[++i], "pps");
            if (!parsed.is_ok()) {
                LOG_ERROR("demo", parsed.error());
                return 64;
            }
            cfg.rate_pps = parsed.value();
        } else if (args[i] == "--i-know-what-im-doing") {
            cfg.override_safety = true;
        } else {
            LOG_ERROR("demo", "Unknown option: " + args[i]);
            return 64;
        }
    }

    if (cfg.rate_pps == 0U || cfg.duration_s == 0U) {
        LOG_ERROR("demo", "--rate and --duration must be greater than zero");
        return 64;
    }

    auto target_check = demo::validate_target(cfg.target_ip, cfg.override_safety);
    if (!target_check.is_ok()) {
        LOG_ERROR("demo", target_check.error());
        return 64;
    }

    util::Result<void> res = util::Result<void>::Ok();
    if (scenario == "syn-flood")
        res = demo::run_syn_flood(cfg);
    else if (scenario == "ping-flood")
        res = demo::run_ping_flood(cfg);
    else if (scenario == "udp-storm")
        res = demo::run_udp_storm(cfg);
    else {
        LOG_ERROR("demo", "Unknown scenario: " + scenario);
        return 64;
    }

    if (!res.is_ok()) {
        LOG_ERROR("demo", "Demo failed: " + res.error());
        return 125;
    }

    LOG_INFO("demo", "Scenario '" + scenario + "' finished successfully");
    return 0;
}

} // namespace cli
