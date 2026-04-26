#include "flow_tracker.h"
#include "../log/log.h"
#include "../util/ipv4.h"
#include <iostream>

namespace core {

FlowTracker::FlowTracker(uint32_t threshold, uint32_t window, bool auto_block, uint32_t block_ttl)
    : syn_threshold(threshold), syn_window_ns(static_cast<uint64_t>(window) * 1000000000ULL),
      auto_block_enabled(auto_block), auto_block_ttl_ns(static_cast<uint64_t>(block_ttl) * 1000000000ULL) {}

void FlowTracker::process_event(const kwatch_event& e) {
    if (e.protocol != 6) return; // Only TCP

    // R2.5/R4.1: Track by 4-tuple
    FlowKey key = {e.src_ip, e.dst_ip, e.sport, e.dport};
    auto& stats = flows[key];

    if (stats.first_seen_ns == 0) stats.first_seen_ns = e.ts_ns;
    stats.last_seen_ns = e.ts_ns;

    if (e.tcp_flags & 0x02) stats.syn_count++; // SYN
    if (e.tcp_flags & 0x10) stats.ack_count++; // ACK

    // Aggregate by Source IP for mitigation decisions
    auto& src_stats = ip_stats[e.src_ip];
    src_stats.syn_count++;
    if (e.tcp_flags & 0x10) src_stats.ack_count++;
    
    // R4.2: Detection logic
    if (!src_stats.is_flagged && src_stats.syn_count >= syn_threshold) {
        // Simple heuristic: if ACKs are < 10% of SYNs after threshold reached
        if (src_stats.ack_count * 10 < src_stats.syn_count) {
            src_stats.is_flagged = true;
            src_stats.last_event_ns = e.ts_ns;
            // R4.2: Essential log string for integration tests
            LOG_WARN("tracker", "SYN_FLOOD detected from " + util::ipv4::format(e.src_ip) + 
                                " (SYNs: " + std::to_string(src_stats.syn_count) + ")");
        }
    }
}

std::vector<uint32_t> FlowTracker::tick_and_get_blocks(uint64_t now_ns) {
    std::vector<uint32_t> new_blocks;
    for (auto& [ip, stats] : ip_stats) {
        if (stats.is_flagged && !stats.is_blocked) {
            if (auto_block_enabled) {
                stats.is_blocked = true;
                stats.block_start_ns = now_ns;
                new_blocks.push_back(ip);
            }
        }
    }
    
    // Clean up old flows to prevent memory exhaustion (R4.4 simulation)
    if (flows.size() > 10000) {
        flows.clear(); 
    }

    return new_blocks;
}

std::vector<uint32_t> FlowTracker::get_expired_blocks(uint64_t now_ns) {
    std::vector<uint32_t> expired;
    for (auto& [ip, stats] : ip_stats) {
        if (stats.is_blocked) {
            if (now_ns > stats.block_start_ns + auto_block_ttl_ns) {
                stats.is_blocked = false;
                stats.is_flagged = false; // Reset state
                stats.syn_count = 0;
                stats.ack_count = 0;
                expired.push_back(ip);
                LOG_INFO("tracker", "Auto-block expired for " + util::ipv4::format(ip));
            }
        }
    }
    return expired;
}

} // namespace core