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
#include <cstdio>
#include <cerrno>
#include <sys/epoll.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <chrono>
#include <ctime>

namespace cli {

struct lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};

static std::string get_rfc3339_time() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::tm tm_buf{};
    gmtime_r(&in_time_t, &tm_buf);
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf);
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

static const char* get_proto_name(uint8_t p) {
    switch (p) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "OTHER";
    }
}

static uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}

int cmd_run(const GlobalOptions& globals, const std::vector<std::string>& args) {
    if (args.empty()) {
        std::fputs("Usage: kwatch run <iface> [--json]\n", stderr);
        return 64;
    }
    std::string if_name = args[0];

    unsigned int if_index = if_nametoindex(if_name.c_str());
    if (if_index == 0) {
        LOG_ERROR("run", "Failed to get index for interface " + if_name);
        return 65; // EX_DATAERR
    }

    int load_err = 0;
    auto skel_res = bpf::Skeleton::open_and_load(&load_err);
    if (!skel_res.is_ok()) {
        // R3.8: distinguish permission errors from other kernel-feature failures.
        if (load_err == EPERM || load_err == EACCES) {
            LOG_ERROR("bpf", "Permission denied loading BPF program. Need CAP_BPF + CAP_NET_ADMIN, or run as root.");
            return 77;
        }
        if (load_err == ENOTSUP || load_err == EOPNOTSUPP || load_err == ENOENT) {
            LOG_ERROR("bpf", "Kernel feature unavailable (missing BTF or XDP support).");
            return 69;
        }
        return 69;
    }
    auto skel = std::move(skel_res.value());

    std::string pin_path = "/sys/fs/bpf/kwatch_" + if_name;
    skel->pin(pin_path);

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
    LOG_INFO("run", "Attached XDP on " + if_name + " (mode=" + attach_res.value() + ")");

    util::SignalHandler sigs;
    if (!sigs.init().is_ok()) return 125;

    core::TickTimer tick;
    if (!tick.init(2).is_ok()) return 125; // 2 Hz

    core::FlowTracker tracker(globals.syn_threshold, globals.syn_window, globals.auto_block, globals.auto_block_ttl);

    bpf::RingBuf ringbuf;
    auto rb_cb = [&globals, &tracker](const kwatch_event& e) {
        tracker.process_event(e);

        std::string src = util::ipv4::format(e.src_ip);
        std::string dst = util::ipv4::format(e.dst_ip);
        const char* proto = get_proto_name(e.protocol);

        if (globals.json) {
            std::fprintf(stdout,
                "{\"ts\":\"%s\",\"ts_ns\":%llu,\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
                "\"sport\":%u,\"dport\":%u,\"protocol\":%u,\"tcp_flags\":%u,"
                "\"ttl\":%u,\"action\":\"%s\"}\n",
                get_rfc3339_time().c_str(),
                (unsigned long long)e.ts_ns,
                src.c_str(), dst.c_str(),
                (unsigned)e.sport, (unsigned)e.dport,
                (unsigned)e.protocol, (unsigned)e.tcp_flags,
                (unsigned)e.ttl,
                e.action == 1 ? "drop" : "pass");
        } else {
            std::fprintf(stdout, "%s %s %s:%u -> %s:%u flags=%s ttl=%u\n",
                get_rfc3339_time().c_str(), proto,
                src.c_str(), (unsigned)e.sport,
                dst.c_str(), (unsigned)e.dport,
                format_tcp_flags(e.tcp_flags).c_str(),
                (unsigned)e.ttl);
        }
        std::fflush(stdout);
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
                const auto& to_block = tracker.tick_and_get_blocks(now_ns);
                const auto& to_unblock = tracker.get_expired_blocks(now_ns);

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
