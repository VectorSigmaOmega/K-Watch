#include "../parser.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <sys/epoll.h>
#include <unistd.h>
#include <unordered_map>

#include <bpf/bpf.h>
#include <net/if.h>

#include "../../bpf/attach.h"
#include "../../bpf/pin_state.h"
#include "../../bpf/ringbuf.h"
#include "../../bpf/skeleton.h"
#include "../../core/flow_snapshot.h"
#include "../../core/flow_tracker.h"
#include "../../core/pps_window.h"
#include "../../core/tick.h"
#include "../../log/log.h"
#include "../../tui/app.h"
#include "../../util/fd.h"
#include "../../util/signals.h"

namespace cli {

namespace {

constexpr size_t kRecentEventCap = 50;
constexpr size_t kThreatSnapshotCap = 16384;
constexpr size_t kFirewallSnapshotCap = 1024;

struct lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};

struct FirewallMeta {
    uint64_t first_seen_ns = 0;
    uint64_t drop_baseline = 0;
};

uint64_t firewall_id(const lpm_key &key) {
    return (static_cast<uint64_t>(key.prefixlen) << 32U) | key.data;
}

uint64_t monotonic_ns() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
}

void refresh_protocol_breakdown(int pkt_fd, tui::ProtocolBreakdown &breakdown) {
    breakdown = {};
    uint32_t current_key = 0;
    uint32_t next_key = 0;
    void *lookup_key = nullptr;
    uint64_t value = 0;

    while (bpf_map_get_next_key(pkt_fd, lookup_key, &next_key) == 0) {
        if (bpf_map_lookup_elem(pkt_fd, &next_key, &value) == 0) {
            switch (next_key) {
            case 1U:
                breakdown.icmp += value;
                break;
            case 6U:
                breakdown.tcp += value;
                break;
            case 17U:
                breakdown.udp += value;
                break;
            case 0xFFFFU:
                breakdown.dropped += value;
                break;
            default:
                breakdown.other += value;
                break;
            }
        }
        current_key = next_key;
        lookup_key = &current_key;
    }
}

void refresh_threat_snapshot(const core::FlowTracker &tracker,
                             std::vector<tui::ThreatRow> &threat_rows) {
    threat_rows.clear();
    const auto &snapshot = tracker.get_snapshot();
    for (const auto &[ip, stats] : snapshot) {
        threat_rows.push_back(tui::ThreatRow{
            ip,
            stats.syn_count,
            stats.ack_count,
            stats.last_ttl,
            stats.is_flagged,
        });
    }

    std::sort(threat_rows.begin(), threat_rows.end(),
              [](const tui::ThreatRow &lhs, const tui::ThreatRow &rhs) {
                  if (lhs.syn_count != rhs.syn_count)
                      return lhs.syn_count > rhs.syn_count;
                  return lhs.ip < rhs.ip;
              });
}

void refresh_firewall_snapshot(int blacklist_fd, std::vector<tui::FirewallRow> &firewall_rows,
                               std::unordered_map<uint64_t, FirewallMeta> &firewall_meta,
                               uint64_t now_ns, uint64_t dropped_total) {
    firewall_rows.clear();
    lpm_key current_key{};
    lpm_key next_key{};
    void *lookup_key = nullptr;

    while (bpf_map_get_next_key(blacklist_fd, lookup_key, &next_key) == 0) {
        const uint64_t id = firewall_id(next_key);
        auto &meta = firewall_meta[id];
        if (meta.first_seen_ns == 0U) {
            meta.first_seen_ns = now_ns;
            meta.drop_baseline = dropped_total;
        }
        firewall_rows.push_back(tui::FirewallRow{
            next_key.prefixlen,
            next_key.data,
            (now_ns - meta.first_seen_ns) / 1000000000ULL,
            dropped_total >= meta.drop_baseline ? dropped_total - meta.drop_baseline : 0U,
        });
        current_key = next_key;
        lookup_key = &current_key;
    }
}

} // namespace

int cmd_top(const GlobalOptions &globals, const std::vector<std::string> &args) {
    if (args.size() != 1) {
        std::fputs("Usage: kwatch top <iface>\n", stderr);
        return 64;
    }
    std::string if_name = args[0];

    unsigned int if_index = if_nametoindex(if_name.c_str());
    if (if_index == 0) {
        LOG_ERROR("top", "Failed to get index for interface " + if_name);
        return 65;
    }

    int load_err = 0;
    auto skel_res = bpf::Skeleton::open_and_load(&load_err, globals.sample_n, globals.syn_window);
    if (!skel_res.is_ok()) {
        if (load_err == EPERM || load_err == EACCES) {
            LOG_ERROR("bpf", "Permission denied loading BPF program. Need CAP_BPF + CAP_NET_ADMIN, "
                             "or run as root.");
            return 77;
        }
        return 69;
    }
    auto skel = std::move(skel_res.value());

    const std::string pin_path = bpf::pin_path_for_iface(if_name);
    const std::string owner_pid_path = bpf::owner_pid_path_for_iface(if_name);
    if (!skel->pin(pin_path, owner_pid_path).is_ok()) {
        return 69;
    }

    bpf::XdpAttach attach(static_cast<int>(if_index));
    int attach_err = 0;
    auto attach_res =
        attach.attach(skel->get()->progs.xdp_kwatch_prog, globals.xdp_mode, &attach_err);
    if (!attach_res.is_ok()) {
        if (attach_err == EPERM || attach_err == EACCES) {
            LOG_ERROR("bpf", "Permission denied attaching XDP. Need CAP_NET_ADMIN.");
            return 77;
        }
        LOG_ERROR("bpf", attach_res.error());
        return 69;
    }
    const std::string actual_mode = attach_res.value();

    util::SignalHandler sigs;
    if (!sigs.init().is_ok())
        return 125;

    core::TickTimer tick;
    if (!tick.init(2).is_ok())
        return 125;

    core::FlowTracker tracker(globals.syn_threshold, globals.syn_window, globals.auto_block,
                              globals.auto_block_ttl);
    core::FlowStateSnapshot flow_snapshot;
    core::PpsWindow pps_win(60);
    std::vector<uint64_t> pps_snapshot;
    pps_snapshot.reserve(60);
    uint64_t current_pps = 0;
    tui::ProtocolBreakdown protocol_breakdown;

    std::vector<kwatch_event> recent_events;
    recent_events.reserve(kRecentEventCap);
    std::mutex events_mutex;
    uint64_t event_drop_count = 0;

    std::vector<tui::ThreatRow> threat_rows;
    threat_rows.reserve(kThreatSnapshotCap);
    std::vector<tui::FirewallRow> firewall_rows;
    firewall_rows.reserve(kFirewallSnapshotCap);
    std::unordered_map<uint64_t, FirewallMeta> firewall_meta;
    firewall_meta.reserve(kFirewallSnapshotCap);

    bpf::RingBuf ringbuf;
    auto rb_cb = [&](const kwatch_event &e) {
        tracker.process_event(e);
        std::lock_guard<std::mutex> lock(events_mutex);
        if (recent_events.size() == kRecentEventCap) {
            recent_events.erase(recent_events.begin());
        }
        recent_events.push_back(e);
    };

    if (!ringbuf.init(bpf_map__fd(skel->get()->maps.events), rb_cb).is_ok()) {
        return 125;
    }

    const int blacklist_fd = bpf_map__fd(skel->get()->maps.blacklist);
    const int flow_state_fd = bpf_map__fd(skel->get()->maps.flow_state);
    const int pkt_fd = bpf_map__fd(skel->get()->maps.pkt_counts);
    const int ringbuf_drops_fd = bpf_map__fd(skel->get()->maps.ringbuf_drops);
    refresh_threat_snapshot(tracker, threat_rows);
    refresh_protocol_breakdown(pkt_fd, protocol_breakdown);
    refresh_firewall_snapshot(blacklist_fd, firewall_rows, firewall_meta, monotonic_ns(),
                              protocol_breakdown.dropped);
    pps_win.copy_snapshot(pps_snapshot);

    tui::App app(if_name, actual_mode, pps_snapshot, current_pps, recent_events, events_mutex,
                 threat_rows, firewall_rows, protocol_breakdown, ringbuf.get_error_count(),
                 event_drop_count, blacklist_fd);
    if (!app.init().is_ok())
        return 125;

    util::UniqueFd epoll_fd(epoll_create1(0));
    if (!epoll_fd.is_valid())
        return 125;

    struct epoll_event ev_sig = {EPOLLIN, {.fd = sigs.get_fd()}};
    struct epoll_event ev_tick = {EPOLLIN, {.fd = tick.get_fd()}};
    struct epoll_event ev_rb = {EPOLLIN, {.fd = ringbuf.get_fd()}};

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sigs.get_fd(), &ev_sig);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tick.get_fd(), &ev_tick);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ringbuf.get_fd(), &ev_rb);

    uint64_t last_pkt_total = 0;
    bool running = true;

    app.render();

    while (running && app.is_running()) {
        struct epoll_event ep_events[3];
        const int n = epoll_wait(epoll_fd, ep_events, 3, -1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            break;

        for (int i = 0; i < n; ++i) {
            if (ep_events[i].data.fd == sigs.get_fd()) {
                const int sig = sigs.read_signal();
                if (sig == SIGINT || sig == SIGTERM) {
                    running = false;
                    break;
                }
                if (sig == SIGSEGV || sig == SIGABRT || sig == SIGILL || sig == SIGFPE) {
                    running = false;
                    break;
                }
            } else if (ep_events[i].data.fd == ringbuf.get_fd()) {
                ringbuf.consume(256);
            } else if (ep_events[i].data.fd == tick.get_fd()) {
                tick.consume();
                app.handle_input();

                // NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
                event_drop_count = ringbuf.get_dropped_count();
                uint32_t drop_key = 0;
                uint64_t kernel_drops = 0;
                if (bpf_map_lookup_elem(ringbuf_drops_fd, &drop_key, &kernel_drops) == 0) {
                    // NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
                    event_drop_count += kernel_drops;
                }

                refresh_protocol_breakdown(pkt_fd, protocol_breakdown);
                const uint64_t current_total = protocol_breakdown.tcp + protocol_breakdown.udp +
                                               protocol_breakdown.icmp + protocol_breakdown.other;
                if (last_pkt_total > 0) {
                    current_pps = (current_total - last_pkt_total) * 2U;
                    pps_win.push(current_pps);
                } else {
                    // NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
                    current_pps = 0;
                }
                last_pkt_total = current_total;

                const uint64_t now_ns = monotonic_ns();
                auto snapshot_res = flow_snapshot.refresh(flow_state_fd);
                if (snapshot_res.is_ok()) {
                    tracker.process_flow_snapshot(flow_snapshot.entries(), now_ns);
                } else {
                    LOG_WARN("top", snapshot_res.error());
                }
                const auto &to_block = tracker.tick_and_get_blocks(now_ns);
                const auto &to_unblock = tracker.get_expired_blocks(now_ns);

                for (uint32_t ip : to_block) {
                    const lpm_key key = {32, ip};
                    uint8_t one = 1;
                    bpf_map_update_elem(blacklist_fd, &key, &one, BPF_ANY);
                }
                for (uint32_t ip : to_unblock) {
                    const lpm_key key = {32, ip};
                    bpf_map_delete_elem(blacklist_fd, &key);
                }

                pps_win.copy_snapshot(pps_snapshot);
                refresh_threat_snapshot(tracker, threat_rows);
                refresh_firewall_snapshot(blacklist_fd, firewall_rows, firewall_meta, now_ns,
                                          protocol_breakdown.dropped);
                app.render();
            }
        }
    }

    skel->unpin(pin_path);
    return 0;
}

} // namespace cli
