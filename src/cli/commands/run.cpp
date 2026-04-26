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
#include <net/if.h>
#include <iostream>
#include <sys/epoll.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <chrono>
#include <iomanip>

namespace cli {

struct lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};

static std::string get_rfc3339_time() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

static std::string format_tcp_flags(uint8_t flags) {
    std::string s;
    if (flags & 0x02) s += "S";
    if (flags & 0x10) s += "A";
    if (flags & 0x08) s += "P";
    if (flags & 0x01) s += "F";
    if (flags & 0x04) s += "R";
    if (s.empty()) s = "-";
    return s;
}

static std::string get_proto_name(uint8_t p) {
    switch (p) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return std::to_string(p);
    }
}

static uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}

int cmd_run(const GlobalOptions& globals, const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Usage: kwatch run <iface>\n";
        return 64;
    }
    std::string if_name = args[0];

    unsigned int if_index = if_nametoindex(if_name.c_str());
    if (if_index == 0) {
        LOG_ERROR("run", "Failed to get index for interface " + if_name);
        return 65; // EX_DATAERR
    }

    auto skel_res = bpf::Skeleton::open_and_load();
    if (!skel_res.is_ok()) {
        // R3.8 Check for permission errors
        if (errno == EPERM) {
            LOG_ERROR("bpf", "Permission denied. Need CAP_BPF, CAP_NET_ADMIN, or root.");
            return 77;
        }
        return 69; // Kernel/BPF issue
    }
    auto skel = std::move(skel_res.value());

    std::string pin_path = "/sys/fs/bpf/kwatch_" + if_name;
    skel->pin(pin_path); // Ignore failure if already exists

    bpf::XdpAttach attach(if_index);
    if (!attach.attach(skel->get()->progs.xdp_kwatch_prog, globals.xdp_mode).is_ok()) {
        return 77; 
    }

    util::SignalHandler sigs;
    if (!sigs.init().is_ok()) return 125;

    core::TickTimer tick;
    if (!tick.init(2).is_ok()) return 125; // 2 Hz loop

    core::FlowTracker tracker(globals.syn_threshold, globals.syn_window, globals.auto_block, globals.auto_block_ttl);

    bpf::RingBuf ringbuf;
    auto rb_cb = [&globals, &tracker](const kwatch_event& e) {
        tracker.process_event(e);

        std::string src = util::ipv4::format(e.src_ip);
        std::string dst = util::ipv4::format(e.dst_ip);
        std::string proto = get_proto_name(e.protocol);

        if (globals.json) {
            std::cout << "{\"ts_ns\":" << e.ts_ns 
                      << ",\"src_ip\":\"" << src << "\""
                      << ",\"dst_ip\":\"" << dst << "\""
                      << ",\"sport\":" << e.sport 
                      << ",\"dport\":" << e.dport 
                      << ",\"protocol\":" << (int)e.protocol 
                      << ",\"tcp_flags\":" << (int)e.tcp_flags 
                      << ",\"ttl\":" << (int)e.ttl 
                      << ",\"action\":\"" << (e.action == 1 ? "drop" : "pass") << "\"}\n";
        } else {
            std::cout << get_rfc3339_time() << " " << proto << " " 
                      << src << ":" << e.sport << " -> " 
                      << dst << ":" << e.dport 
                      << " flags=" << format_tcp_flags(e.tcp_flags) 
                      << " ttl=" << (int)e.ttl << "\n";
        }
        std::cout.flush();
    };

    if (!ringbuf.init(bpf_map__fd(skel->get()->maps.events), rb_cb).is_ok()) {
        return 125;
    }

    util::UniqueFd epoll_fd(epoll_create1(0));
    if (!epoll_fd.is_valid()) return 125;

    struct epoll_event ev_sig = { EPOLLIN, { .fd = sigs.get_fd() } };
    struct epoll_event ev_tick = { EPOLLIN, { .fd = tick.get_fd() } };
    struct epoll_event ev_rb = { EPOLLIN, { .fd = ringbuf.get_fd() } };
    
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sigs.get_fd(), &ev_sig);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tick.get_fd(), &ev_tick);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ringbuf.get_fd(), &ev_rb);

    LOG_INFO("run", "Running on " + if_name + ". Press Ctrl+C to stop.");

    int blacklist_fd = bpf_map__fd(skel->get()->maps.blacklist);
    bool running = true;

    while (running) {
        struct epoll_event ep_events[3];
        int n = epoll_wait(epoll_fd, ep_events, 3, -1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) break;

        for (int i = 0; i < n; i++) {
            if (ep_events[i].data.fd == sigs.get_fd()) {
                int sig = sigs.read_signal();
                if (sig == SIGINT || sig == SIGTERM) {
                    LOG_INFO("run", "Termination signal received, exiting...");
                    running = false;
                    break;
                }
            } else if (ep_events[i].data.fd == ringbuf.get_fd()) {
                ringbuf.consume();
            } else if (ep_events[i].data.fd == tick.get_fd()) {
                tick.consume();
                
                uint64_t now_ns = get_time_ns();
                auto to_block = tracker.tick_and_get_blocks(now_ns);
                auto to_unblock = tracker.get_expired_blocks(now_ns);

                for (uint32_t ip : to_block) {
                    struct lpm_key key = {32, ip};
                    uint8_t val = 1;
                    bpf_map_update_elem(blacklist_fd, &key, &val, BPF_ANY);
                    LOG_WARN("run", "Auto-blocked IP: " + util::ipv4::format(ip));
                }

                for (uint32_t ip : to_unblock) {
                    struct lpm_key key = {32, ip};
                    bpf_map_delete_elem(blacklist_fd, &key);
                    LOG_INFO("run", "Auto-unblocked IP: " + util::ipv4::format(ip));
                }
            }
        }
    }

    skel->unpin(pin_path);
    return 0;
}

} // namespace cli