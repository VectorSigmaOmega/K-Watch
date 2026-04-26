#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "kwatch_shared.h"

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define ETH_P_8021Q 0x8100

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, uint32_t);   // Protocol (IPPROTO_TCP, ETH_P_ARP, etc. or custom 0xFFFF for drops)
    __type(value, uint64_t); // Count
} pkt_counts SEC(".maps");

struct lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_key);
    __type(value, uint8_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KiB
} events SEC(".maps");

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;
    uint16_t dport;
};

struct flow_val {
    uint32_t syn_count;
    uint32_t ack_count;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} flow_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 60);
    __type(key, uint32_t);
    __type(value, uint64_t);
} pps_window SEC(".maps");

volatile const __u32 sample_n = 100;

static __always_inline void inc_count(uint32_t proto) {
    uint64_t *count = bpf_map_lookup_elem(&pkt_counts, &proto);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        uint64_t init_val = 1;
        bpf_map_update_elem(&pkt_counts, &proto, &init_val, BPF_ANY);
    }
}

SEC("xdp")
int xdp_kwatch_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    uint16_t h_proto = BPF_CORE_READ(eth, h_proto);
    int hdr_offset = sizeof(struct ethhdr);

    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = data + hdr_offset;
        if ((void *)(vlan + 1) > data_end) return XDP_PASS;
        h_proto = BPF_CORE_READ(vlan, h_vlan_encapsulated_proto);
        hdr_offset += sizeof(struct vlan_hdr);
    }

    if (h_proto == bpf_htons(ETH_P_ARP)) {
        inc_count(ETH_P_ARP);
        return XDP_PASS;
    }

    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        inc_count(ETH_P_IPV6);
        return XDP_PASS;
    }

    if (h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + hdr_offset;
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    uint32_t src_ip = BPF_CORE_READ(ip, saddr);
    uint32_t dst_ip = BPF_CORE_READ(ip, daddr);
    uint8_t protocol = BPF_CORE_READ(ip, protocol);
    uint8_t ttl = BPF_CORE_READ(ip, ttl);

    uint8_t version_ihl = 0;
    bpf_probe_read_kernel(&version_ihl, 1, ip);
    uint8_t ihl = version_ihl & 0x0F;
    hdr_offset += (ihl * 4);
    if (hdr_offset < sizeof(struct ethhdr) + sizeof(struct iphdr)) return XDP_PASS;

    inc_count(protocol);

    struct lpm_key b_key = {};
    b_key.prefixlen = 32;
    b_key.data = src_ip;
    
    uint8_t action = 0; // PASS
    if (bpf_map_lookup_elem(&blacklist, &b_key)) {
        action = 1; // DROP
        inc_count(0xFFFF); // Count drops globally
    }

    uint16_t sport = 0, dport = 0;
    uint8_t tcp_flags = 0;

    if (protocol == 6) { // TCP
        struct tcphdr *tcp = data + hdr_offset;
        if ((void *)(tcp + 1) <= data_end) {
            sport = BPF_CORE_READ(tcp, source);
            dport = BPF_CORE_READ(tcp, dest);
            
            uint8_t *flags_ptr = ((uint8_t *)tcp) + 13;
            if ((void *)(flags_ptr + 1) <= data_end) {
                bpf_probe_read_kernel(&tcp_flags, 1, flags_ptr);
            }
        }
    } else if (protocol == 17) { // UDP
        struct udphdr *udp = data + hdr_offset;
        if ((void *)(udp + 1) <= data_end) {
            sport = BPF_CORE_READ(udp, source);
            dport = BPF_CORE_READ(udp, dest);
        }
    } else if (protocol == 1) { // ICMP
        struct icmphdr *icmp = data + hdr_offset;
        if ((void *)(icmp + 1) <= data_end) {
            uint8_t type = BPF_CORE_READ(icmp, type);
            uint8_t code = BPF_CORE_READ(icmp, code);
            sport = ((uint16_t)type << 8) | code;
        }
    }

    struct flow_key f_key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .sport = sport,
        .dport = dport
    };

    struct flow_val *f_val = bpf_map_lookup_elem(&flow_state, &f_key);
    bool is_new_flow = false;

    uint64_t now = bpf_ktime_get_ns();

    if (!f_val) {
        is_new_flow = true;
        struct flow_val new_val = {0};
        new_val.first_seen_ns = now;
        new_val.last_seen_ns = now;
        if (protocol == 6 && (tcp_flags & 0x02)) { // SYN
            new_val.syn_count = 1;
        }
        bpf_map_update_elem(&flow_state, &f_key, &new_val, BPF_ANY);
    } else {
        f_val->last_seen_ns = now;
        if (protocol == 6) {
            if (tcp_flags & 0x02) __sync_fetch_and_add(&f_val->syn_count, 1);
            if (tcp_flags & 0x10) __sync_fetch_and_add(&f_val->ack_count, 1);
        }
    }

    bool should_emit = is_new_flow;
    if (!should_emit) {
        if (bpf_get_prandom_u32() % sample_n == 0) {
            should_emit = true;
        }
    }

    if (should_emit) {
        struct kwatch_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->ts_ns = now;
            e->src_ip = src_ip;
            e->dst_ip = dst_ip;
            e->sport = sport;
            e->dport = dport;
            e->protocol = protocol;
            e->tcp_flags = tcp_flags;
            e->ttl = ttl;
            e->action = action;
            bpf_ringbuf_submit(e, 0);
        }
    }

    return action == 1 ? XDP_DROP : XDP_PASS;
}