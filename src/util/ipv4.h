#pragma once
#include <string>
#include <cstdint>
#include <utility>
#include "result.h"

namespace util {
namespace ipv4 {

util::Result<uint32_t> parse(const std::string& ip);
util::Result<std::pair<uint32_t, uint8_t>> parse_cidr(const std::string& cidr);
std::string format(uint32_t ip);

} // namespace ipv4
} // namespace util