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
#include <iostream>
#include <sys/epoll.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <chrono>
#include <mutex>

namespace cli {

int cmd_top(const GlobalOptions& globals, const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: kwatch top <iface>\n";
        return 64;
    }
    std::string if_name = args[0];

    unsigned int if_index = if_nametoindex(if_name.c_str());
    if (if_index == 0) {
        LOG_ERROR("top", "Failed to get index for interface " + if_name);
        return 65;
    }

    auto skel_res = bpf::Skeleton::open_and_load();
    if (!skel_res.is_ok()) return 69;
    auto skel = std::move(skel_res.value());

    std::string pin_path = "/sys/fs/bpf/kwatch_" + if_name;
    (void)skel->pin(pin_path);

    bpf::XdpAttach attach(if_index);
    if (!attach.attach(skel->get()->progs.xdp_kwatch_prog, globals.xdp_mode).is_ok()) {
        return 77;
    }

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

    // Determine actual mode for display (R3.2 logic)
    // For now we pass the requested one, but we should query.
    tui::App app(if_name, globals.xdp_mode, pps_win, recent_events, events_mutex, tracker,
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

    while (running && app.is_running()) {
        app.handle_input();
        app.render();

        struct epoll_event ep_events[3];
        int n = epoll_wait(epoll_fd, ep_events, 3, 100); 
        if (n < 0 && errno == EINTR) continue;

        for (int i = 0; i < n; i++) {
            if (ep_events[i].data.fd == sigs.get_fd()) {
                int sig = sigs.read_signal();
                if (sig == SIGINT || sig == SIGTERM) {
                    running = false;
                    break;
                }
            } else if (ep_events[i].data.fd == ringbuf.get_fd()) {
                ringbuf.consume();
            } else if (ep_events[i].data.fd == tick.get_fd()) {
                tick.consume();
                
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
                    pps_win.push((current_total - last_pkt_total) * 2); 
                }
                last_pkt_total = current_total;

                // Flow tracker re-blocking/expiry
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
            }
        }
    }

    skel->unpin(pin_path);
    return 0;
}

} // namespace cli