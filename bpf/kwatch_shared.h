#ifndef KWATCH_SHARED_H
#define KWATCH_SHARED_H

#ifdef __cplusplus
#include <cstdint>
#endif

struct kwatch_event {
    uint64_t ts_ns;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol;
    uint8_t tcp_flags;
    uint8_t ttl;
    uint8_t action; // 0 = pass, 1 = drop
};

#endif
