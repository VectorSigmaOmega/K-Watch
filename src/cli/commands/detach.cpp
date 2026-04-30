#include "../../log/log.h"
#include "../parser.h"
#include <bpf/libbpf.h>
#include <cstdio>
#include <net/if.h>

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif
#ifndef XDP_FLAGS_HW_MODE
#define XDP_FLAGS_HW_MODE (1U << 3)
#endif

namespace cli {

int cmd_detach(const GlobalOptions &globals, const std::vector<std::string> &args) {
    (void)globals;
    if (args.size() != 1) {
        std::fputs("Usage: kwatch detach <iface>\n", stderr);
        return 64;
    }
    std::string if_name = args[0];
    unsigned int raw_if_index = if_nametoindex(if_name.c_str());
    if (raw_if_index == 0) {
        LOG_ERROR("detach", "Failed to get index for interface " + if_name);
        return 65;
    }
    int if_index = static_cast<int>(raw_if_index);

    bpf_xdp_detach(if_index, XDP_FLAGS_HW_MODE, NULL);
    bpf_xdp_detach(if_index, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(if_index, XDP_FLAGS_SKB_MODE, NULL);
    bpf_xdp_detach(if_index, 0, NULL);

    LOG_INFO("detach", "Detached any XDP program from " + if_name);
    return 0;
}

} // namespace cli
