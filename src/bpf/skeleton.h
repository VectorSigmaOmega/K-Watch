#pragma once
#include "../util/result.h"
#include "kwatch.skel.h"
#include <cstdint>
#include <memory>
#include <string>

namespace bpf {

class Skeleton {
    struct kwatch_bpf *skel;
    std::string pinned_path;

    Skeleton(struct kwatch_bpf *s);

  public:
    ~Skeleton();

    // No copy
    Skeleton(const Skeleton &) = delete;
    Skeleton &operator=(const Skeleton &) = delete;

    // Move
    Skeleton(Skeleton &&other) noexcept;
    Skeleton &operator=(Skeleton &&other) noexcept;

    // err_out (if non-null) receives the positive errno from the failing
    // libbpf call, or 0 on success. Lets callers distinguish EPERM from
    // other failures (R3.8) without sniffing a stale global errno.
    static util::Result<std::unique_ptr<Skeleton>>
    open_and_load(int *err_out = nullptr, uint32_t sample_n = 100, uint32_t syn_window_s = 10);

    util::Result<void> pin(const std::string &path);
    void unpin(const std::string &path);

    struct kwatch_bpf *get() const { return skel; }
};

} // namespace bpf
