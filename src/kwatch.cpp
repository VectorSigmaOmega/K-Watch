#include <iostream>
#include <vector>
#include <string>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kwatch.skel.h"

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif

static volatile bool keep_running = true;

static void sig_handler(int sig) {
    keep_running = false;
}

void print_stats(int fd) {
    uint32_t key, next_key;
    uint64_t value;
    
    key = 0;
    std::cout << "\033[2J\033[H"; // Clear screen
    std::cout << "--- K-Watch Live Packet Stats ---" << std::endl;
    std::cout << "Protocol\tCount" << std::endl;
    std::cout << "---------------------------------" << std::endl;

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            std::string proto_name;
            switch (next_key) {
                case 1: proto_name = "ICMP"; break;
                case 6: proto_name = "TCP"; break;
                case 17: proto_name = "UDP"; break;
                default: proto_name = "Other (" + std::to_string(next_key) + ")"; break;
            }
            std::cout << proto_name << "\t\t" << value << std::endl;
        }
        key = next_key;
    }
}

int main(int argc, char **argv) {
    struct kwatch_bpf *skel;
    int err;
    const char *if_name = "lo";
    const char *block_ip = nullptr;

    if (argc > 1) {
        if_name = argv[1];
    }
    if (argc > 3 && std::string(argv[2]) == "--block") {
        block_ip = argv[3];
    }

    unsigned int if_index = if_nametoindex(if_name);
    if (if_index == 0) {
        std::cerr << "Failed to get index for interface " << if_name << std::endl;
        return 1;
    }

    libbpf_set_print(NULL);

    skel = kwatch_bpf__open();
    if (!skel) {
        std::cerr << "Failed to open BPF skeleton" << std::endl;
        return 1;
    }

    err = kwatch_bpf__load(skel);
    if (err) {
        std::cerr << "Failed to load BPF skeleton" << std::endl;
        goto cleanup;
    }

    // Add to blacklist if requested
    if (block_ip) {
        uint32_t ip_addr;
        if (inet_pton(AF_INET, block_ip, &ip_addr) != 1) {
            std::cerr << "Invalid IP address: " << block_ip << std::endl;
            goto cleanup;
        }
        uint8_t dummy = 1;
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.blacklist), &ip_addr, &dummy, BPF_ANY);
        if (err) {
            std::cerr << "Failed to update blacklist map" << std::endl;
            goto cleanup;
        }
        std::cout << "Blocked IP: " << block_ip << std::endl;
    }

    // Attach to XDP with SKB mode (Generic XDP)
    skel->links.xdp_kwatch_prog = bpf_program__attach_xdp(skel->progs.xdp_kwatch_prog, if_index);
    // Note: libbpf's attach_xdp doesn't directly take flags in this simple API.
    // For specific flags, we usually use bpf_xdp_attach(if_index, prog_fd, flags, NULL).
    // Let's use the more explicit call if we want SKB mode.
    
    if (!skel->links.xdp_kwatch_prog) {
        // Fallback or explicit attach
        int prog_fd = bpf_program__fd(skel->progs.xdp_kwatch_prog);
        err = bpf_xdp_attach(if_index, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err < 0) {
            std::cerr << "Failed to attach XDP program in SKB mode" << std::endl;
            goto cleanup;
        }
        std::cout << "Attached XDP in SKB mode." << std::endl;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    std::cout << "K-Watch attached to " << if_name << " (index " << if_index << ")" << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;

    while (keep_running) {
        print_stats(bpf_map__fd(skel->maps.pkt_counts));
        sleep(1);
    }

cleanup:
    kwatch_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
