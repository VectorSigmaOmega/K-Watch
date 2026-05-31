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

struct kwatch_runtime_config {
    unsigned int sample_n;
    unsigned long long syn_window_ns;
};

static inline struct kwatch_runtime_config kwatch_make_runtime_config(unsigned int sample_n,
                                                                      unsigned int syn_window_s) {
    struct kwatch_runtime_config cfg;
    cfg.sample_n = sample_n;
    cfg.syn_window_ns = (unsigned long long)syn_window_s * 1000000000ULL;
    return cfg;
}

static inline int kwatch_should_emit_event(unsigned int sample_n, unsigned int random_value,
                                           int is_new) {
    if (is_new || sample_n <= 1U) {
        return 1;
    }
    return (random_value % sample_n) == 0U ? 1 : 0;
}

#ifdef __cplusplus
}
#endif
