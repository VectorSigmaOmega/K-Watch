#pragma once
#include "../util/result.h"
#include <arpa/inet.h>
#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <vector>

namespace demo {

struct DemoConfig {
    std::string target_ip;
    uint16_t target_port;
    uint32_t rate_pps;
    uint32_t duration_s;
    bool override_safety;
};

inline util::Result<void> validate_target(const std::string &ip, bool override_safety) {
    struct in_addr ipv4 {};
    const bool valid_ipv4 = inet_pton(AF_INET, ip.c_str(), &ipv4) == 1;
    const bool is_ipv4_loopback = valid_ipv4 && ((ntohl(ipv4.s_addr) & 0xff000000U) == 0x7f000000U);

    if (!valid_ipv4) {
        return util::Result<void>::Err("Invalid IPv4 target address " + ip);
    }
    if (!is_ipv4_loopback && !override_safety) {
        return util::Result<void>::Err("Refusing to target non-loopback address " + ip +
                                       " without --i-know-what-im-doing");
    }
    return util::Result<void>::Ok();
}

util::Result<void> run_ping_flood(const DemoConfig &cfg);
util::Result<void> run_syn_flood(const DemoConfig &cfg);
util::Result<void> run_udp_storm(const DemoConfig &cfg);

} // namespace demo
