#pragma once
#include <functional>
#include <memory>
#include <bpf/libbpf.h>
#include "../../bpf/kwatch_shared.h"
#include "../util/result.h"

namespace bpf {

class RingBuf {
    struct ring_buffer *rb;
public:
    using Callback = std::function<void(const kwatch_event&)>;
private:
    std::unique_ptr<Callback> cb_ptr;

public:
    RingBuf();
    ~RingBuf();

    util::Result<void> init(int map_fd, Callback cb);
    int get_fd() const;
    void consume();
};

} // namespace bpf