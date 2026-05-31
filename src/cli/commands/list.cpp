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
        LOG_ERROR("list", "No active kwatch owner for " + if_name);
        return -1;
    }
    std::string map_path = pin_path + "/blacklist";
    int fd = bpf_obj_get(map_path.c_str());
    if (fd < 0) {
        LOG_ERROR("list",
                  "Failed to open map at " + map_path + " (is kwatch running on " + if_name + "?)");
    }
    return fd;
}

int cmd_list(const GlobalOptions &globals, const std::vector<std::string> &args) {
    (void)globals;
    if (args.size() != 1) {
        std::fputs("Usage: kwatch list <iface>\n", stderr);
        return 64;
    }
    std::string if_name = args[0];
    util::UniqueFd fd(get_blacklist_fd(if_name));
    if (!fd.is_valid())
        return 65;

    struct lpm_key next_key;
    struct lpm_key current_key = {0, 0};
    void *lookup_key = nullptr;
    uint8_t value;

    while (bpf_map_get_next_key(fd, lookup_key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            std::fprintf(stdout, "%s/%u\n", util::ipv4::format(next_key.data).c_str(),
                         next_key.prefixlen);
        }
        current_key = next_key;
        lookup_key = &current_key;
    }

    return 0;
}

} // namespace cli
