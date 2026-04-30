#include "flow_tracker.h"
#include "../log/log.h"
#include "../util/ipv4.h"

namespace core {

FlowTracker::FlowTracker(uint32_t threshold, uint32_t window, bool auto_block, uint32_t block_ttl)
    : syn_threshold(threshold), syn_window_ns(static_cast<uint64_t>(window) * 1000000000ULL),
      auto_block_enabled(auto_block),
      auto_block_ttl_ns(static_cast<uint64_t>(block_ttl) * 1000000000ULL) {
    block_scratch.reserve(kMaxIpStats); // R3.5: Avoid reallocation
    unblock_scratch.reserve(kMaxIpStats);
    aggregate_scratch.reserve(kMaxIpStats);
    aggregate_index.reserve(kMaxIpStats);
}

void FlowTracker::process_event(const kwatch_event &e) {
    auto &src_stats = ip_stats[e.src_ip];
    if (e.ttl != 0) {
        src_stats.last_ttl = e.ttl; // R5.7: display metadata still comes from sampled events.
    }
    if (e.ts_ns > src_stats.last_event_ns) {
        src_stats.last_event_ns = e.ts_ns;
    }
}

void FlowTracker::process_flow_snapshot(const std::vector<FlowMapEntry> &entries, uint64_t now_ns) {
    aggregate_scratch.clear();
    aggregate_index.clear();

    for (const auto &entry : entries) {
        if (entry.key.protocol != 6U || entry.stats.last_seen_ns == 0U) {
            continue;
        }
        if (now_ns > entry.stats.last_seen_ns &&
            now_ns - entry.stats.last_seen_ns > syn_window_ns) {
            continue;
        }
        if (entry.stats.first_seen_ns != 0U && now_ns > entry.stats.first_seen_ns &&
            now_ns - entry.stats.first_seen_ns > syn_window_ns) {
            continue;
        }

        auto found = aggregate_index.find(entry.key.src_ip);
        if (found == aggregate_index.end()) {
            const size_t index = aggregate_scratch.size();
            aggregate_index.emplace(entry.key.src_ip, index);
            aggregate_scratch.push_back(FlowAggregate{
                entry.key.src_ip,
                entry.stats.syn_count,
                entry.stats.ack_count,
                entry.stats.last_seen_ns,
            });
        } else {
            auto &aggregate = aggregate_scratch[found->second];
            aggregate.syn_count += entry.stats.syn_count;
            aggregate.ack_count += entry.stats.ack_count;
            if (entry.stats.last_seen_ns > aggregate.last_seen_ns) {
                aggregate.last_seen_ns = entry.stats.last_seen_ns;
            }
        }
    }

    ++snapshot_generation;
    if (snapshot_generation == 0U) {
        ++snapshot_generation;
    }

    for (const auto &aggregate : aggregate_scratch) {
        auto &stats = ip_stats[aggregate.src_ip];
        stats.syn_count = aggregate.syn_count;
        stats.ack_count = aggregate.ack_count;
        stats.last_event_ns = aggregate.last_seen_ns;
        stats.snapshot_generation = snapshot_generation;

        const uint32_t unmatched =
            stats.syn_count > stats.ack_count ? stats.syn_count - stats.ack_count : 0U;
        if (!stats.is_flagged && unmatched >= syn_threshold) {
            stats.is_flagged = true;
            LOG_WARN("tracker", "SYN_FLOOD detected from " + util::ipv4::format(aggregate.src_ip) +
                                    " unmatched_syns=" + std::to_string(unmatched));
        }
    }

    for (auto &[ip, stats] : ip_stats) {
        if (stats.snapshot_generation == snapshot_generation || stats.is_blocked) {
            continue;
        }
        if (stats.last_event_ns == 0U ||
            (now_ns > stats.last_event_ns && now_ns - stats.last_event_ns > syn_window_ns)) {
            stats.syn_count = 0;
            stats.ack_count = 0;
            stats.is_flagged = false;
        }
    }
}

void FlowTracker::evict_idle(uint64_t now_ns) {
    if (flows.size() > kMaxFlows / 2) {
        for (auto it = flows.begin(); it != flows.end();) {
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
        for (auto it = ip_stats.begin(); it != ip_stats.end();) {
            bool idle = now_ns > it->second.last_event_ns + kFlowIdleTtlNs;
            if (idle && !it->second.is_flagged && !it->second.is_blocked) {
                it = ip_stats.erase(it);
            } else {
                ++it;
            }
        }
    }
}

const std::vector<uint32_t> &FlowTracker::tick_and_get_blocks(uint64_t now_ns) {
    block_scratch.clear();
    for (auto &[ip, stats] : ip_stats) {
        if (stats.is_flagged && !stats.is_blocked && auto_block_enabled) {
            stats.is_blocked = true;
            stats.block_start_ns = now_ns;
            block_scratch.push_back(ip);
        }
    }
    evict_idle(now_ns);
    return block_scratch;
}

const std::vector<uint32_t> &FlowTracker::get_expired_blocks(uint64_t now_ns) {
    unblock_scratch.clear();
    for (auto &[ip, stats] : ip_stats) {
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
