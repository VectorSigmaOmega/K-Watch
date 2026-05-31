#pragma once
#include <cstdint>
#include <vector>

namespace core {

class PpsWindow {
    std::vector<uint64_t> window;
    size_t head;
    size_t count;

  public:
    PpsWindow(size_t size = 60);

    void push(uint64_t pps);
    void copy_snapshot(std::vector<uint64_t> &out) const;
    uint64_t latest() const;
    std::vector<uint64_t> get_snapshot() const; // Returns oldest to newest
    uint64_t current_average() const;
};

} // namespace core
