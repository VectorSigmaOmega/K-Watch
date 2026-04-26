#include "pps_window.h"

namespace core {

PpsWindow::PpsWindow(size_t size) : window(size, 0), head(0), count(0) {}

void PpsWindow::push(uint64_t pps) {
    if (window.empty()) return;
    window[head] = pps;
    head = (head + 1) % window.size();
    if (count < window.size()) count++;
}

std::vector<uint64_t> PpsWindow::get_snapshot() const {
    std::vector<uint64_t> result;
    result.reserve(count);
    if (count == 0) return result;

    size_t start = (count < window.size()) ? 0 : head;
    for (size_t i = 0; i < count; ++i) {
        result.push_back(window[(start + i) % window.size()]);
    }
    return result;
}

uint64_t PpsWindow::current_average() const {
    if (count == 0) return 0;
    uint64_t sum = 0;
    for (size_t i = 0; i < count; ++i) sum += window[i];
    return sum / count;
}

} // namespace core