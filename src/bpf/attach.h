#pragma once
#include <string>
#include <bpf/libbpf.h>
#include "../util/result.h"

namespace bpf {

class XdpAttach {
    int if_index;
    int link_fd = -1;

public:
    explicit XdpAttach(int index);
    ~XdpAttach();

    XdpAttach(const XdpAttach&) = delete;
    XdpAttach& operator=(const XdpAttach&) = delete;

    XdpAttach(XdpAttach&& other) noexcept;
    XdpAttach& operator=(XdpAttach&& other) noexcept;

    util::Result<void> attach(struct bpf_program* prog, const std::string& mode);
    void detach();
};

} // namespace bpf
