#pragma once
#include <string>
#include <memory>
#include "../util/result.h"
#include "kwatch.skel.h"

namespace bpf {

class Skeleton {
    struct kwatch_bpf* skel;

    Skeleton(struct kwatch_bpf* s);
public:
    ~Skeleton();

    // No copy
    Skeleton(const Skeleton&) = delete;
    Skeleton& operator=(const Skeleton&) = delete;
    
    // Move
    Skeleton(Skeleton&& other) noexcept;
    Skeleton& operator=(Skeleton&& other) noexcept;

    static util::Result<std::unique_ptr<Skeleton>> open_and_load();

    util::Result<void> pin(const std::string& path);
    void unpin(const std::string& path);

    struct kwatch_bpf* get() const { return skel; }
};

} // namespace bpf