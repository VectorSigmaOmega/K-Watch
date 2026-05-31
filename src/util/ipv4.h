#pragma once
#include "result.h"
#include <cstdint>
#include <string>
#include <utility>

namespace util {
namespace ipv4 {

util::Result<uint32_t> parse(const std::string &ip);
util::Result<std::pair<uint32_t, uint8_t>> parse_cidr(const std::string &cidr);
std::string format(uint32_t ip);

} // namespace ipv4
} // namespace util