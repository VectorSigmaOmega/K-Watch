#include "../parser.h"
#include "../../log/log.h"
#include "../../bpf/skeleton.h"
#include "../../bpf/attach.h"
#include "../../bpf/ringbuf.h"
#include "../../util/signals.h"
#include "../../util/ipv4.h"
#include "../../util/fd.h"
#include "../../core/tick.h"
#include "../../core/flow_tracker.h"
#include "../../core/pps_window.h"
#include "../../tui/app.h"
#include <net/if.h>
#include <cstdio>
#include <cerrno>
#include <sys/epoll.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <chrono>
#include <mutex>

namespace cli {

int cmd_top(const GlobalOptions& globals, const std::vector<std::string>& args) {
    if (args.empty()) {
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
    auto skel_res = bpf::Skeleton::open_and_load(&load_err);
    if (!skel_res.is_ok()) {
        if (load_err == EPERM || load_err == EACCES) {
            LOG_ERROR("bpf", "Permission denied loading BPF program. Need CAP_BPF + CAP_NET_ADMIN, or run as root.");
            return 77;
        }
        return 69;
    }
    auto skel = std::move(skel_res.value());

    std::string pin_path = "/sys/fs/bpf/kwatch_" + if_name;
    (void)skel->pin(pin_path);

    bpf::XdpAttach attach(static_cast<int>(if_index));
    int attach_err = 0;
    auto attach_res = attach.attach(skel->get()->progs.xdp_kwatch_prog, globals.xdp_mode, &attach_err);
    if (!attach_res.is_ok()) {
        if (attach_err == EPERM || attach_err == EACCES) {
            LOG_ERROR("bpf", "Permission denied attaching XDP. Need CAP_NET_ADMIN.");
            return 77;
        }
        LOG_ERROR("bpf", attach_res.error());
        return 69;
    }
    std::string actual_mode = attach_res.value();

    util::SignalHandler sigs;
    if (!sigs.init().is_ok()) return 125;

    core::TickTimer tick;
    if (!tick.init(2).is_ok()) return 125;

    core::FlowTracker tracker(globals.syn_threshold, globals.syn_window, globals.auto_block, globals.auto_block_ttl);
    core::PpsWindow pps_win(60);

    std::vector<kwatch_event> recent_events;
    std::mutex events_mutex;

    bpf::RingBuf ringbuf;
    auto rb_cb = [&](const kwatch_event& e) {
        tracker.process_event(e);
        std::lock_guard<std::mutex> lock(events_mutex);
        recent_events.push_back(e);
        if (recent_events.size() > 50) recent_events.erase(recent_events.begin());
    };

    if (!ringbuf.init(bpf_map__fd(skel->get()->maps.events), rb_cb).is_ok()) {
        return 125;
    }

    tui::App app(if_name, actual_mode, pps_win, recent_events, events_mutex, tracker,
                 [&ringbuf]() { return ringbuf.get_dropped_count(); },
                 bpf_map__fd(skel->get()->maps.pkt_counts),
                 bpf_map__fd(skel->get()->maps.blacklist));
    if (!app.init().is_ok()) return 125;

    util::UniqueFd epoll_fd(epoll_create1(0));
    if (!epoll_fd.is_valid()) return 125;

    struct epoll_event ev_sig = { EPOLLIN, { .fd = sigs.get_fd() } };
    struct epoll_event ev_tick = { EPOLLIN, { .fd = tick.get_fd() } };
    struct epoll_event ev_rb = { EPOLLIN, { .fd = ringbuf.get_fd() } };

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sigs.get_fd(), &ev_sig);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tick.get_fd(), &ev_tick);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ringbuf.get_fd(), &ev_rb);

    uint64_t last_pkt_total = 0;
    bool running = true;
    int blacklist_fd = bpf_map__fd(skel->get()->maps.blacklist);

    // R5.3: render only on tick (2 Hz). Keystrokes are polled at the same rate.
    app.render();

    while (running && app.is_running()) {
        struct epoll_event ep_events[3];
        int n = epoll_wait(epoll_fd, ep_events, 3, -1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) break;

        for (int i = 0; i < n; i++) {
            if (ep_events[i].data.fd == sigs.get_fd()) {
                int sig = sigs.read_signal();
                if (sig == SIGINT || sig == SIGTERM) { running = false; break; }
            } else if (ep_events[i].data.fd == ringbuf.get_fd()) {
                ringbuf.consume();
            } else if (ep_events[i].data.fd == tick.get_fd()) {
                tick.consume();

                // Drain any pending keypresses since the last tick.
                app.handle_input();

                // Sample pkt_counts to derive PPS.
                uint64_t current_total = 0;
                uint32_t key = 0, next_key;
                uint64_t val;
                int pkt_fd = bpf_map__fd(skel->get()->maps.pkt_counts);
                while (bpf_map_get_next_key(pkt_fd, &key, &next_key) == 0) {
                    if (bpf_map_lookup_elem(pkt_fd, &next_key, &val) == 0) {
                        if (next_key != 0xFFFF) current_total += val;
                    }
                    key = next_key;
                }
                if (last_pkt_total > 0) {
                    pps_win.push((current_total - last_pkt_total) * 2); // delta over 500ms × 2 = pps
                }
                last_pkt_total = current_total;

                uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                const auto& to_block = tracker.tick_and_get_blocks(now_ns);
                const auto& to_unblock = tracker.get_expired_blocks(now_ns);

                for (uint32_t ip : to_block) {
                    struct { uint32_t p; uint32_t d; } lpm = {32, ip};
                    uint8_t one = 1;
                    bpf_map_update_elem(blacklist_fd, &lpm, &one, BPF_ANY);
                }
                for (uint32_t ip : to_unblock) {
                    struct { uint32_t p; uint32_t d; } lpm = {32, ip};
                    bpf_map_delete_elem(blacklist_fd, &lpm);
                }

                app.render();
            }
        }
    }

    skel->unpin(pin_path);
    return 0;
}

} // namespace cli
