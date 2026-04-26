#include "../parser.h"
#include "../../util/ipv4.h"
#include "../../util/fd.h"
#include <iostream>
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
        std::cerr << "Failed to open map at " << map_path << " (is kwatch running on " << if_name << "?)\n";
    }
    return fd;
}

int cmd_block(const GlobalOptions& globals, const std::vector<std::string>& args) {
    (void)globals;
    if (args.size() < 2) {
        std::cerr << "Usage: kwatch block <iface> <ip/cidr> [<ip>...]\n";
        return 64;
    }
    std::string if_name = args[0];
    util::UniqueFd fd(get_blacklist_fd(if_name));
    if (!fd.is_valid()) return 65;

    bool all_ok = true;
    for (size_t i = 1; i < args.size(); ++i) {
        auto res = util::ipv4::parse_cidr(args[i]);
        if (!res.is_ok()) {
            std::cerr << "Failed to parse: " << args[i] << " - " << res.error() << "\n";
            all_ok = false;
            continue;
        }

        struct lpm_key key;
        key.prefixlen = res.value().second;
        key.data = res.value().first;
        uint8_t val = 1;

        if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
            std::cerr << "Failed to add " << args[i] << " to blacklist map.\n";
            all_ok = false;
        } else {
            std::cerr << "Blocked: " << args[i] << "\n";
        }
    }

    return all_ok ? 0 : 65;
}

} // namespace cli