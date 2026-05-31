#include "../../bpf/pin_state.h"
#include "../../log/log.h"
#include "../../util/fd.h"
#include "../parser.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstdio>
#include <unistd.h>

namespace cli {

int cmd_stats(const GlobalOptions &globals, const std::vector<std::string> &args) {
    (void)globals;
    if (args.size() != 1) {
        std::fputs("Usage: kwatch stats <iface>\n", stderr);
        return 64;
    }

    std::string if_name = args[0];
    std::string pin_path = bpf::pin_path_for_iface(if_name);
    auto owner = bpf::read_owner_state(bpf::owner_pid_path_for_iface(if_name));
    if (!owner.is_ok() || !bpf::is_owner_alive(owner.value())) {
        LOG_ERROR("stats", "No active kwatch owner for " + if_name);
        return 65;
    }
    std::string map_path = pin_path + "/pkt_counts";

    util::UniqueFd fd(bpf_obj_get(map_path.c_str()));
    if (!fd.is_valid()) {
        LOG_ERROR("stats",
                  "Failed to open map at " + map_path + " (is kwatch running on " + if_name + "?)");
        return 65;
    }

    uint32_t key = 0, next_key;
    uint64_t value;

    std::fputs("Protocol\tCount\n---------------------------------\n", stdout);

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            const char *proto_name = "Other";
            char other_buf[32];
            switch (next_key) {
            case 1:
                proto_name = "ICMP";
                break;
            case 6:
                proto_name = "TCP";
                break;
            case 17:
                proto_name = "UDP";
                break;
            case 0xFFFF:
                proto_name = "DROPPED";
                break;
            default:
                std::snprintf(other_buf, sizeof(other_buf), "Other (%u)", next_key);
                proto_name = other_buf;
                break;
            }
            std::fprintf(stdout, "%s\t\t%lu\n", proto_name, (unsigned long)value);
        }
        key = next_key;
    }

    return 0;
}

} // namespace cli
