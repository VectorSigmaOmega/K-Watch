#include "ipv4.h"
#include <arpa/inet.h>
#include <vector>

namespace util {
namespace ipv4 {

util::Result<uint32_t> parse(const std::string &ip) {
    uint32_t addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return util::Result<uint32_t>::Err("Invalid IPv4 address format");
    }
    return util::Result<uint32_t>::Ok(addr);
}

util::Result<std::pair<uint32_t, uint8_t>> parse_cidr(const std::string &cidr) {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        auto res = parse(cidr);
        if (res.is_ok())
            return util::Result<std::pair<uint32_t, uint8_t>>::Ok({res.value(), 32});
        return util::Result<std::pair<uint32_t, uint8_t>>::Err("Invalid CIDR format");
    }

    std::string ip_part = cidr.substr(0, slash_pos);
    std::string prefix_part = cidr.substr(slash_pos + 1);

    auto ip_res = parse(ip_part);
    if (!ip_res.is_ok())
        return util::Result<std::pair<uint32_t, uint8_t>>::Err("Invalid IP in CIDR");

    try {
        size_t pos = 0;
        int prefix = std::stoi(prefix_part, &pos);
        if (pos != prefix_part.size())
            return util::Result<std::pair<uint32_t, uint8_t>>::Err("Invalid prefix in CIDR");
        if (prefix < 0 || prefix > 32)
            return util::Result<std::pair<uint32_t, uint8_t>>::Err("Prefix out of range");
        return util::Result<std::pair<uint32_t, uint8_t>>::Ok(
            {ip_res.value(), static_cast<uint8_t>(prefix)});
    } catch (...) {
        return util::Result<std::pair<uint32_t, uint8_t>>::Err("Invalid prefix in CIDR");
    }
}

std::string format(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN)) {
        return std::string(buf);
    }
    return "<invalid>";
}

} // namespace ipv4
} // namespace util
