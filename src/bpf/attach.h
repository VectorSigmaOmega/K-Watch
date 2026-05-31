#pragma once
#include "../util/result.h"
#include <bpf/libbpf.h>
#include <string>

namespace bpf {

class XdpAttach {
    int if_index;
    int link_fd = -1;

  public:
    explicit XdpAttach(int index);
    ~XdpAttach();

    XdpAttach(const XdpAttach &) = delete;
    XdpAttach &operator=(const XdpAttach &) = delete;

    XdpAttach(XdpAttach &&other) noexcept;
    XdpAttach &operator=(XdpAttach &&other) noexcept;

    // Returns the mode that actually attached ("drv" / "skb" / "generic" / "hw").
    // err_out receives positive errno on failure.
    util::Result<std::string> attach(struct bpf_program *prog, const std::string &mode,
                                     int *err_out = nullptr);
    void detach();
};

} // namespace bpf
