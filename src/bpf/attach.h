#pragma once
#include <string>
#include <bpf/libbpf.h>
#include "../util/result.h"

namespace bpf {

class XdpAttach {
    int if_index;
    struct bpf_link* link = nullptr;

public:
    explicit XdpAttach(int index);
    ~XdpAttach();

    // No copy
    XdpAttach(const XdpAttach&) = delete;
    XdpAttach& operator=(const XdpAttach&) = delete;

    // Move
    XdpAttach(XdpAttach&& other) noexcept;
    XdpAttach& operator=(XdpAttach&& other) noexcept;

    util::Result<void> attach(struct bpf_program* prog, const std::string& mode);
    void detach();
};

} // namespace bpf