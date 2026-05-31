#include "../../bpf/pin_state.h"
#include "../../log/log.h"
#include "../../util/fd.h"
#include "../../util/ipv4.h"
#include "../parser.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstdio>
#include <unistd.h>

namespace cli {

struct lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};

static int get_blacklist_fd(const std::string &if_name) {
    std::string pin_path = bpf::pin_path_for_iface(if_name);
    auto owner = bpf::read_owner_state(bpf::owner_pid_path_for_iface(if_name));
    if (!owner.is_ok() || !bpf::is_owner_alive(owner.value())) {
        LOG_ERROR("block", "No active kwatch owner for " + if_name);
        return -1;
    }
    std::string map_path = pin_path + "/blacklist";
    int fd = bpf_obj_get(map_path.c_str());
    if (fd < 0) {
        LOG_ERROR("block",
                  "Failed to open map at " + map_path + " (is kwatch running on " + if_name + "?)");
    }
    return fd;
}

int cmd_block(const GlobalOptions &globals, const std::vector<std::string> &args) {
    (void)globals;
    if (args.size() < 2) {
        std::fputs("Usage: kwatch block <iface> <ip/cidr> [<ip>...]\n", stderr);
        return 64;
    }
    std::string if_name = args[0];
    util::UniqueFd fd(get_blacklist_fd(if_name));
    if (!fd.is_valid())
        return 65;

    bool all_ok = true;
    for (size_t i = 1; i < args.size(); ++i) {
        auto res = util::ipv4::parse_cidr(args[i]);
        if (!res.is_ok()) {
            LOG_ERROR("block", "Failed to parse '" + args[i] + "': " + res.error());
            all_ok = false;
            continue;
        }

        struct lpm_key key;
        key.prefixlen = res.value().second;
        key.data = res.value().first;
        uint8_t val = 1;

        if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
            LOG_ERROR("block", "Failed to add " + args[i] + " to blacklist map");
            all_ok = false;
        } else {
            LOG_INFO("block", "Blocked: " + args[i]);
        }
    }

    return all_ok ? 0 : 65;
}

} // namespace cli
