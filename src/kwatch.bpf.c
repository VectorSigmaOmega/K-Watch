#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, uint32_t);   // IP Protocol (TCP, UDP, ICMP, etc.)
    __type(value, uint64_t); // Packet Count
} pkt_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);   // IPv4 Address
    __type(value, uint8_t);  // Dummy value
} blacklist SEC(".maps");

SEC("xdp")
int xdp_kwatch_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Check Blacklist
    uint32_t src_ip = ip->saddr;
    if (bpf_map_lookup_elem(&blacklist, &src_ip)) {
        return XDP_DROP;
    }

    // Update Counts
    uint32_t protocol = ip->protocol;
    uint64_t *count = bpf_map_lookup_elem(&pkt_counts, &protocol);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        uint64_t init_val = 1;
        bpf_map_update_elem(&pkt_counts, &protocol, &init_val, BPF_ANY);
    }

    return XDP_PASS;
}
