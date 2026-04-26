#include "../parser.h"
#include "../../log/log.h"
#include "../../util/fd.h"
#include <iostream>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

namespace cli {

int cmd_stats(const GlobalOptions& globals, const std::vector<std::string>& args) {
    (void)globals;
    if (args.empty()) {
        std::cerr << "Usage: kwatch stats <iface>\n";
        return 64;
    }
    
    std::string if_name = args[0];
    std::string map_path = "/sys/fs/bpf/kwatch_" + if_name + "/pkt_counts";

    util::UniqueFd fd(bpf_obj_get(map_path.c_str()));
    if (!fd.is_valid()) {
        std::cerr << "Failed to open map at " << map_path << " (is kwatch running on " << if_name << "?)\n";
        return 65;
    }

    uint32_t key = 0, next_key;
    uint64_t value;
    
    std::cout << "Protocol\tCount\n";
    std::cout << "---------------------------------\n";

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            std::string proto_name;
            switch (next_key) {
                case 1: proto_name = "ICMP"; break;
                case 6: proto_name = "TCP"; break;
                case 17: proto_name = "UDP"; break;
                case 0xFFFF: proto_name = "DROPPED"; break;
                default: proto_name = "Other (" + std::to_string(next_key) + ")"; break;
            }
            std::cout << proto_name << "\t\t" << value << "\n";
        }
        key = next_key;
    }

    return 0;
}

} // namespace cli