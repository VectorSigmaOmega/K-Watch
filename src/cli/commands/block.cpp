#include "../parser.h"
#include "../../log/log.h"
#include "../../util/ipv4.h"
#include "../../util/fd.h"
#include <cstdio>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

namespace cli {

struct lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};

static int get_blacklist_fd(const std::string& if_name) {
    std::string map_path = "/sys/fs/bpf/kwatch_" + if_name + "/blacklist";
    int fd = bpf_obj_get(map_path.c_str());
    if (fd < 0) {
        LOG_ERROR("block", "Failed to open map at " + map_path + " (is kwatch running on " + if_name + "?)");
    }
    return fd;
}

int cmd_block(const GlobalOptions& globals, const std::vector<std::string>& args) {
    (void)globals;
    if (args.size() < 2) {
        std::fputs("Usage: kwatch block <iface> <ip/cidr> [<ip>...]\n", stderr);
        return 64;
    }
    std::string if_name = args[0];
    util::UniqueFd fd(get_blacklist_fd(if_name));
    if (!fd.is_valid()) return 65;

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