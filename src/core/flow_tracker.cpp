#include "flow_tracker.h"
#include "../log/log.h"
#include "../util/ipv4.h"

namespace core {

FlowTracker::FlowTracker(uint32_t threshold, uint32_t window, bool auto_block, uint32_t block_ttl)
    : syn_threshold(threshold), syn_window_ns(static_cast<uint64_t>(window) * 1000000000ULL),
      auto_block_enabled(auto_block), auto_block_ttl_ns(static_cast<uint64_t>(block_ttl) * 1000000000ULL) {
    block_scratch.reserve(kMaxIpStats); // R3.5: Avoid reallocation
    unblock_scratch.reserve(kMaxIpStats);
}

void FlowTracker::process_event(const kwatch_event& e) {
    if (e.protocol != 6) return; // TCP only

    FlowKey key = {e.src_ip, e.dst_ip, e.sport, e.dport};
    auto& stats = flows[key];
    if (stats.first_seen_ns == 0) stats.first_seen_ns = e.ts_ns;
    stats.last_seen_ns = e.ts_ns;
    if (e.tcp_flags & 0x02) stats.syn_count++;
    if (e.tcp_flags & 0x10) stats.ack_count++;

    auto& src_stats = ip_stats[e.src_ip];
    src_stats.last_ttl = e.ttl; // R5.7: track TTL for OS heuristic

    // Slide the per-IP counting window.
    if (src_stats.last_event_ns > 0 && e.ts_ns > src_stats.last_event_ns + syn_window_ns) {
        src_stats.syn_count = 0;
        src_stats.ack_count = 0;
        if (!src_stats.is_blocked) src_stats.is_flagged = false;
    }
    src_stats.last_event_ns = e.ts_ns;

    if (e.tcp_flags & 0x02) src_stats.syn_count++;
    if (e.tcp_flags & 0x10) src_stats.ack_count++;

    // R4.2: flag when SYNs-without-matching-ACKs >= threshold within window.
    uint32_t unmatched = src_stats.syn_count > src_stats.ack_count
                       ? src_stats.syn_count - src_stats.ack_count : 0;
    if (!src_stats.is_flagged && unmatched >= syn_threshold) {
        src_stats.is_flagged = true;
        LOG_WARN("tracker", "SYN_FLOOD detected from " + util::ipv4::format(e.src_ip)
                 + " (unmatched SYNs: " + std::to_string(unmatched) + ")");
    }
}

void FlowTracker::evict_idle(uint64_t now_ns) {
    if (flows.size() > kMaxFlows / 2) {
        for (auto it = flows.begin(); it != flows.end(); ) {
            if (now_ns > it->second.last_seen_ns + kFlowIdleTtlNs) {
                it = flows.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (flows.size() > kMaxFlows) {
        flows.clear(); // last-resort cap; LRU map in BPF is the real store
    }

    if (ip_stats.size() > kMaxIpStats) {
        // Evict idle, unflagged, unblocked entries first.
        for (auto it = ip_stats.begin(); it != ip_stats.end(); ) {
            bool idle = now_ns > it->second.last_event_ns + kFlowIdleTtlNs;
            if (idle && !it->second.is_flagged && !it->second.is_blocked) {
                it = ip_stats.erase(it);
            } else {
                ++it;
            }
        }
    }
}

const std::vector<uint32_t>& FlowTracker::tick_and_get_blocks(uint64_t now_ns) {
    block_scratch.clear();
    for (auto& [ip, stats] : ip_stats) {
        if (stats.is_flagged && !stats.is_blocked && auto_block_enabled) {
            stats.is_blocked = true;
            stats.block_start_ns = now_ns;
            block_scratch.push_back(ip);
        }
    }
    evict_idle(now_ns);
    return block_scratch;
}

const std::vector<uint32_t>& FlowTracker::get_expired_blocks(uint64_t now_ns) {
    unblock_scratch.clear();
    for (auto& [ip, stats] : ip_stats) {
        if (stats.is_blocked && now_ns >= stats.block_start_ns + auto_block_ttl_ns) {
            stats.is_blocked = false;
            stats.is_flagged = false;
            stats.syn_count = 0;
            stats.ack_count = 0;
            unblock_scratch.push_back(ip);
            LOG_INFO("tracker", "Auto-block expired for " + util::ipv4::format(ip));
        }
    }
    return unblock_scratch;
}

} // namespace core
