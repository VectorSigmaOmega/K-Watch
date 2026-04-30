#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Shared event structure for the ring buffer
struct kwatch_event {
    unsigned long long ts_ns;
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short sport;
    unsigned short dport;
    unsigned char protocol;
    unsigned char tcp_flags;
    unsigned char ttl;
    unsigned char action; // 0 = pass, 1 = drop
    unsigned char icmp_type;
    unsigned char icmp_code;
};

// R4.1: Flow tracking keys
struct kwatch_flow_key {
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short sport;
    unsigned short dport;
    unsigned char protocol;
};

struct kwatch_flow_stats {
    unsigned int syn_count;
    unsigned int ack_count;
    unsigned long long first_seen_ns;
    unsigned long long last_seen_ns;
};

#ifdef __cplusplus
}
#endif
