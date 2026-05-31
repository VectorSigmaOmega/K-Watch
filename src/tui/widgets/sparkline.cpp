#include "sparkline.h"
#include <algorithm>

namespace tui {
namespace widgets {

static const char *bars[] = {" ", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"};

std::string render_sparkline(const std::vector<uint64_t> &data, int width) {
    if (data.empty() || width <= 0)
        return "";

    std::string result;
    size_t n = data.size();
    size_t start = (n > static_cast<size_t>(width)) ? (n - static_cast<size_t>(width)) : 0;

    uint64_t max_val = 0;
    for (size_t i = start; i < n; ++i)
        if (data[i] > max_val)
            max_val = data[i];

    if (max_val == 0)
        max_val = 1;

    for (size_t i = start; i < n; ++i) {
        int idx = static_cast<int>((data[i] * 8) / max_val);
        if (idx > 8)
            idx = 8;
        result += bars[idx];
    }
    return result;
}

} // namespace widgets
} // namespace tui