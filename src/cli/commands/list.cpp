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

int cmd_list(const GlobalOptions& globals, const std::vector<std::string>& args) {
    (void)globals;
    if (args.empty()) {
        std::cerr << "Usage: kwatch list <iface>\n";
        return 64;
    }
    std::string if_name = args[0];
    util::UniqueFd fd(get_blacklist_fd(if_name));
    if (!fd.is_valid()) return 65;

    struct lpm_key key = {0, 0};
    struct lpm_key next_key;
    uint8_t value;

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            std::cout << util::ipv4::format(next_key.data) << "/" << next_key.prefixlen << "\n";
        }
        key = next_key;
    }

    return 0;
}

} // namespace cli