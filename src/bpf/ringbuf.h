#pragma once
#include "../../bpf/kwatch_shared.h"
#include "../util/result.h"
#include <bpf/libbpf.h>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace bpf {

class RingBuf {
    struct ring_buffer *rb;

  public:
    using Callback = std::function<void(const kwatch_event &)>;

  private:
    std::unique_ptr<Callback> cb_ptr;

  public:
    RingBuf();
    ~RingBuf();

    util::Result<void> init(int map_fd, Callback cb);
    int get_fd() const;
    void consume(size_t budget = 1024);
    const uint64_t &get_error_count() const { return error_count; }
    uint64_t get_dropped_count() const { return dropped_count; }
    int dispatch_event(void *data, size_t size);

  private:
    uint64_t error_count = 0;
    uint64_t dropped_count = 0;
    size_t callback_budget = 0;
    size_t callbacks_this_drain = 0;
};

} // namespace bpf
