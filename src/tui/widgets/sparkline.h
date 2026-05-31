#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace tui {
namespace widgets {

std::string render_sparkline(const std::vector<uint64_t> &data, int width);

} // namespace widgets
} // namespace tui