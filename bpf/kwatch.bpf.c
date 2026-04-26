#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "kwatch_shared.h"

// R2.3: Standard EtherTypes
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct { __u32 prefixlen; __u32 data; });
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct kwatch_flow_key);
    __type(value, struct kwatch_flow_stats);
} flow_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} pkt_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 60);
    __type(key, __u32);
    __type(value, __u64);
} pps_window SEC(".maps");

static __always_inline void inc_count(__u32 proto) {
    __u64 *cnt = bpf_map_lookup_elem(&pkt_counts, &proto);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&pkt_counts, &proto, &one, BPF_NOEXIST);
    }
}

volatile const __u32 sample_n = 100;

// Helper to emit sampled events including the action (pass/drop)
static __always_inline void emit_event(struct xdp_md *ctx, __u32 src, __u32 dst, __u8 proto, __u8 ttl, __u8 action, bool is_new) {
    if (!is_new && (bpf_get_prandom_u32() % sample_n != 0)) return;

    struct kwatch_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    e->ts_ns = bpf_ktime_get_ns();
    e->src_ip = src;
    e->dst_ip = dst;
    e->protocol = proto;
    e->ttl = ttl;
    e->action = action;
    e->sport = 0;
    e->dport = 0;
    e->tcp_flags = 0;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    void *l3_ptr = (void *)(eth + 1);

    // Re-parse ports and flags for the event
    struct iphdr *ip = l3_ptr;
    if ((void *)(ip + 1) <= data_end) {
        void *l4_ptr = (void *)ip + (ip->ihl * 4);
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcp = l4_ptr;
            if ((void *)(tcp + 1) <= data_end) {
                e->sport = bpf_ntohs(tcp->source);
                e->dport = bpf_ntohs(tcp->dest);
                e->tcp_flags = ((__u8 *)tcp)[13];
            }
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udp = l4_ptr;
            if ((void *)(udp + 1) <= data_end) {
                e->sport = bpf_ntohs(udp->source);
                e->dport = bpf_ntohs(udp->dest);
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("xdp")
int xdp_kwatch_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 eth_type = bpf_ntohs(eth->h_proto);
    void *l3_ptr = (void *)(eth + 1);
    
    if (eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD) {
        struct vlan_hdr *vlan = l3_ptr;
        if ((void *)(vlan + 1) > data_end) return XDP_PASS;
        eth_type = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        l3_ptr = (void *)(vlan + 1);
    }

    if (eth_type != ETH_P_IP) {
        if (eth_type == ETH_P_IPV6) inc_count(0x86DD);
        else if (eth_type == ETH_P_ARP) inc_count(0x0806);
        return XDP_PASS;
    }

    struct iphdr *ip = l3_ptr;
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u8 proto = ip->protocol;
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // Blacklist check (R2.5)
    struct { __u32 prefixlen; __u32 data; } key = {32, src_ip};
    if (bpf_map_lookup_elem(&blacklist, &key)) {
        inc_count(0xFFFF); 
        emit_event(ctx, src_ip, dst_ip, proto, ip->ttl, 1, true); // always emit drops
        return XDP_DROP;
    }

    inc_count(proto);

    struct kwatch_flow_key fkey = {0};
    fkey.src_ip = src_ip;
    fkey.dst_ip = dst_ip;
    fkey.protocol = proto;

    __u8 tcp_flags = 0;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            fkey.sport = bpf_ntohs(tcp->source);
            fkey.dport = bpf_ntohs(tcp->dest);
            tcp_flags = ((__u8 *)tcp)[13];
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            fkey.sport = bpf_ntohs(udp->source);
            fkey.dport = bpf_ntohs(udp->dest);
        }
    }

    struct kwatch_flow_stats *stats = bpf_map_lookup_elem(&flow_state, &fkey);
    bool is_new = false;
    if (!stats) {
        struct kwatch_flow_stats new_stats = {0};
        new_stats.first_seen_ns = bpf_ktime_get_ns();
        new_stats.last_seen_ns = new_stats.first_seen_ns;
        if (tcp_flags & 0x02) new_stats.syn_count = 1;
        if (tcp_flags & 0x10) new_stats.ack_count = 1;
        bpf_map_update_elem(&flow_state, &fkey, &new_stats, BPF_NOEXIST);
        is_new = true;
    } else {
        stats->last_seen_ns = bpf_ktime_get_ns();
        // R4.1: per-flow SYN/ACK accounting in the flow_state map.
        if (tcp_flags & 0x02) __sync_fetch_and_add(&stats->syn_count, 1);
        if (tcp_flags & 0x10) __sync_fetch_and_add(&stats->ack_count, 1);
    }

    emit_event(ctx, src_ip, dst_ip, proto, ip->ttl, 0, is_new);

    return XDP_PASS;
}
