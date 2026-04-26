#include "attach.h"
#include "../log/log.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <unistd.h>

namespace bpf {

XdpAttach::XdpAttach(int index) : if_index(index) {}

XdpAttach::~XdpAttach() {
    detach();
}

XdpAttach::XdpAttach(XdpAttach&& other) noexcept : if_index(other.if_index), link_fd(other.link_fd) {
    other.link_fd = -1;
}

XdpAttach& XdpAttach::operator=(XdpAttach&& other) noexcept {
    if (this != &other) {
        detach();
        if_index = other.if_index;
        link_fd = other.link_fd;
        other.link_fd = -1;
    }
    return *this;
}

void XdpAttach::detach() {
    if (link_fd >= 0) {
        // Closing the link FD releases the kernel-side bpf_link, which
        // detaches the XDP program. The kernel performs this same release
        // automatically when the process dies (including SIGSEGV) — that is
        // how R3.3 is satisfied.
        close(link_fd);
        link_fd = -1;
        LOG_INFO("bpf", "XDP detached from interface index " + std::to_string(if_index));
    }
}

util::Result<void> XdpAttach::attach(struct bpf_program* prog, const std::string& requested_mode) {
    detach();

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        return util::Result<void>::Err("Invalid BPF program fd");
    }

    auto try_mode = [&](__u32 flags, const char* name) -> int {
        LIBBPF_OPTS(bpf_link_create_opts, opts);
        opts.flags = flags;
        int fd = bpf_link_create(prog_fd, if_index, BPF_XDP, &opts);
        if (fd >= 0) {
            LOG_INFO("bpf", std::string("XDP attached mode=") + name);
        }
        return fd;
    };

    int fd = -1;
    if (requested_mode == "drv") {
        fd = try_mode(XDP_FLAGS_DRV_MODE, "drv");
    } else if (requested_mode == "skb") {
        fd = try_mode(XDP_FLAGS_SKB_MODE, "skb");
    } else if (requested_mode == "hw") {
        fd = try_mode(XDP_FLAGS_HW_MODE, "hw");
    } else {
        // R3.2 auto: try drv → skb → unspecified
        fd = try_mode(XDP_FLAGS_DRV_MODE, "drv");
        if (fd < 0) fd = try_mode(XDP_FLAGS_SKB_MODE, "skb");
        if (fd < 0) fd = try_mode(0, "generic");
    }

    if (fd < 0) {
        return util::Result<void>::Err("Failed to attach XDP in mode=" + requested_mode);
    }

    link_fd = fd;
    return util::Result<void>::Ok();
}

} // namespace bpf
