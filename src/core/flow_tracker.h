#pragma once
#include "../../bpf/kwatch_shared.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {

struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const FlowKey &other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port &&
               dst_port == other.dst_port;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey &k) const {
        return std::hash<uint32_t>{}(k.src_ip) ^ std::hash<uint32_t>{}(k.dst_ip) ^
               (std::hash<uint16_t>{}(k.src_port) << 1) ^ (std::hash<uint16_t>{}(k.dst_port) << 2);
    }
};

struct FlowStats {
    uint32_t syn_count = 0;
    uint32_t ack_count = 0;
    uint64_t first_seen_ns = 0;
    uint64_t last_seen_ns = 0;
};

struct FlowMapEntry {
    kwatch_flow_key key{};
    kwatch_flow_stats stats{};
};

struct FlowAggregate {
    uint32_t src_ip = 0;
    uint32_t syn_count = 0;
    uint32_t ack_count = 0;
    uint64_t last_seen_ns = 0;
};

struct IpStats {
    uint32_t syn_count = 0;
    uint32_t ack_count = 0;
    uint64_t last_event_ns = 0;
    uint64_t block_start_ns = 0;
    uint64_t snapshot_generation = 0;
    bool is_flagged = false;
    bool is_blocked = false;
    uint8_t last_ttl = 0; // R5.7: track TTL for OS heuristic
};

class FlowTracker {
    uint32_t syn_threshold;
    uint64_t syn_window_ns;
    bool auto_block_enabled;
    uint64_t auto_block_ttl_ns;

    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows;
    std::unordered_map<uint32_t, IpStats> ip_stats;
    std::unordered_map<uint32_t, size_t> aggregate_index;
    std::vector<FlowAggregate> aggregate_scratch;
    uint64_t snapshot_generation = 0;

    static constexpr size_t kMaxFlows = 65536;
    static constexpr size_t kMaxIpStats = 16384;
    static constexpr uint64_t kFlowIdleTtlNs = 60ULL * 1000000000ULL; // 60s

    // R3.5: pre-sized scratch buffers reused across ticks; no per-tick allocation.
    std::vector<uint32_t> block_scratch;
    std::vector<uint32_t> unblock_scratch;

    void evict_idle(uint64_t now_ns);

  public:
    FlowTracker(uint32_t threshold, uint32_t window, bool auto_block, uint32_t block_ttl);

    void process_event(const kwatch_event &e);
    void process_flow_snapshot(const std::vector<FlowMapEntry> &entries, uint64_t now_ns);

    // Returns newly flagged IPs that should be auto-blocked. The returned
    // reference is valid until the next call to tick_and_get_blocks.
    const std::vector<uint32_t> &tick_and_get_blocks(uint64_t now_ns);

    // Returns IPs whose auto-block TTL has expired. The returned reference
    // is valid until the next call to get_expired_blocks.
    const std::vector<uint32_t> &get_expired_blocks(uint64_t now_ns);

    // Returns a snapshot of current flow stats for TUI
    const std::unordered_map<uint32_t, IpStats> &get_snapshot() const { return ip_stats; }
};

} // namespace core
