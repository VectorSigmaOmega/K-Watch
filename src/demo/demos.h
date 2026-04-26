#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "../util/result.h"

namespace demo {

struct DemoConfig {
    std::string target_ip;
    uint16_t target_port;
    uint32_t rate_pps;
    uint32_t duration_s;
    bool override_safety;
};

inline util::Result<void> validate_target(const std::string& ip, bool override_safety) {
    if (ip != "127.0.0.1" && ip != "::1" && !override_safety) {
        return util::Result<void>::Err("Refusing to target non-loopback address " + ip + " without --i-know-what-im-doing");
    }
    return util::Result<void>::Ok();
}

util::Result<void> run_ping_flood(const DemoConfig& cfg);
util::Result<void> run_syn_flood(const DemoConfig& cfg);
util::Result<void> run_udp_storm(const DemoConfig& cfg);

} // namespace demo