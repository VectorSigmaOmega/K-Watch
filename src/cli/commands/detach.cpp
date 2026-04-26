#include "../parser.h"
#include "../../log/log.h"
#include <bpf/libbpf.h>
#include <net/if.h>
#include <iostream>

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

int cmd_detach(const GlobalOptions& globals, const std::vector<std::string>& args) {
    (void)globals;
    if (args.empty()) {
        std::cerr << "Usage: kwatch detach <iface>\n";
        return 64;
    }
    std::string if_name = args[0];
    unsigned int if_index = if_nametoindex(if_name.c_str());
    if (if_index == 0) {
        std::cerr << "Failed to get index for interface " << if_name << "\n";
        return 65;
    }

    // Attempt to detach in all modes, idempotently.
    bpf_xdp_detach(if_index, XDP_FLAGS_HW_MODE, NULL);
    bpf_xdp_detach(if_index, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(if_index, XDP_FLAGS_SKB_MODE, NULL);
    bpf_xdp_detach(if_index, 0, NULL);

    std::cout << "Successfully detached any XDP program from " << if_name << ".\n";
    return 0;
}

} // namespace cli