#include "ringbuf.h"
#include "../log/log.h"
#include <utility>

namespace bpf {

static int handle_event(void *ctx, void *data, size_t size) {
    auto *self = static_cast<RingBuf *>(ctx);
    if (!self)
        return 0;
    return self->dispatch_event(data, size);
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

    rb = ring_buffer__new(map_fd, handle_event, this, NULL);
    if (!rb) {
        LOG_ERROR("bpf", "Failed to create ring buffer");
        return util::Result<void>::Err("ring_buffer__new failed");
    }

    return util::Result<void>::Ok();
}

int RingBuf::get_fd() const {
    if (!rb)
        return -1;
    return ring_buffer__epoll_fd(rb);
}

int RingBuf::dispatch_event(void *data, size_t size) {
    if (size < sizeof(kwatch_event))
        return 0;
    if (callback_budget > 0 && callbacks_this_drain >= callback_budget) {
        ++dropped_count;
        return 1;
    }
    const auto *e = static_cast<const kwatch_event *>(data);
    if (cb_ptr && *cb_ptr) {
        (*cb_ptr)(*e);
    }
    ++callbacks_this_drain;
    return 0;
}

void RingBuf::consume(size_t budget) {
    if (rb) {
        callback_budget = budget;
        callbacks_this_drain = 0;
        int err = ring_buffer__consume(rb);
        callback_budget = 0;
        if (err < 0 && err != -EINTR) {
            error_count++;
        }
    }
}

} // namespace bpf
