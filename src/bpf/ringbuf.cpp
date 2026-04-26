#include "ringbuf.h"
#include "../log/log.h"

namespace bpf {

static int handle_event(void *ctx, void *data, size_t size) {
    if (size < sizeof(kwatch_event)) return 0;
    auto* cb = static_cast<RingBuf::Callback*>(ctx);
    const auto* e = static_cast<const kwatch_event*>(data);
    if (cb && *cb) {
        (*cb)(*e);
    }
    return 0;
}

RingBuf::RingBuf() : rb(nullptr) {}

RingBuf::~RingBuf() {
    if (rb) {
        ring_buffer__free(rb);
        rb = nullptr;
    }
}

util::Result<void> RingBuf::init(int map_fd, Callback cb) {
    cb_ptr = std::make_unique<Callback>(std::move(cb));
    
    rb = ring_buffer__new(map_fd, handle_event, cb_ptr.get(), NULL);
    if (!rb) {
        LOG_ERROR("bpf", "Failed to create ring buffer");
        return util::Result<void>::Err("ring_buffer__new failed");
    }

    return util::Result<void>::Ok();
}

int RingBuf::get_fd() const {
    if (!rb) return -1;
    return ring_buffer__epoll_fd(rb);
}

void RingBuf::consume() {
    if (rb) {
        int err = ring_buffer__poll(rb, 0); // 0 timeout, non-blocking
        if (err < 0 && err != -EINTR) {
            dropped_count++;
        }
    }
}

} // namespace bpf