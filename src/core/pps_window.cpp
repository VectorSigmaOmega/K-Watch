#include "pps_window.h"

namespace core {

PpsWindow::PpsWindow(size_t size) : window(size, 0), head(0), count(0) {}

void PpsWindow::push(uint64_t pps) {
    if (window.empty())
        return;
    window[head] = pps;
    head = (head + 1) % window.size();
    if (count < window.size())
        count++;
}

void PpsWindow::copy_snapshot(std::vector<uint64_t> &out) const {
    out.clear();
    if (count == 0)
        return;

    size_t start = (count < window.size()) ? 0 : head;
    for (size_t i = 0; i < count; ++i) {
        out.push_back(window[(start + i) % window.size()]);
    }
}

uint64_t PpsWindow::latest() const {
    if (count == 0 || window.empty())
        return 0;
    const size_t idx = (head == 0) ? (window.size() - 1) : (head - 1);
    return window[idx];
}

std::vector<uint64_t> PpsWindow::get_snapshot() const {
    std::vector<uint64_t> result;
    result.reserve(count);
    copy_snapshot(result);
    return result;
}

uint64_t PpsWindow::current_average() const {
    if (count == 0)
        return 0;
    uint64_t sum = 0;
    for (size_t i = 0; i < count; ++i)
        sum += window[i];
    return sum / count;
}

} // namespace core
