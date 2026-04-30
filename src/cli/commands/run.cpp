#include "../../bpf/attach.h"
#include "../../bpf/ringbuf.h"
#include "../../bpf/skeleton.h"
#include "../../core/event_formatter.h"
#include "../../core/flow_snapshot.h"
#include "../../core/flow_tracker.h"
#include "../../core/tick.h"
#include "../../log/log.h"
#include "../../util/fd.h"
#include "../../util/ipv4.h"
#include "../../util/signals.h"
#include "../parser.h"
#include <bpf/bpf.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <net/if.h>
#include <sys/epoll.h>
#include <unistd.h>

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

static uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

int cmd_run(const GlobalOptions &globals, const std::vector<std::string> &args) {
    if (args.size() != 1) {
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
    auto skel_res = bpf::Skeleton::open_and_load(&load_err, globals.sample_n, globals.syn_window);
    if (!skel_res.is_ok()) {
        // R3.8: distinguish permission errors from other kernel-feature failures.
        if (load_err == EPERM || load_err == EACCES) {
            LOG_ERROR("bpf", "Permission denied loading BPF program. Need CAP_BPF + CAP_NET_ADMIN, "
                             "or run as root.");
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
    if (!skel->pin(pin_path).is_ok()) {
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
    LOG_INFO("run", "Attached XDP on " + if_name + " (mode=" + attach_res.value() + ")");

    util::SignalHandler sigs;
    if (!sigs.init().is_ok())
        return 125;

    core::TickTimer tick;
    if (!tick.init(2).is_ok())
        return 125; // 2 Hz

    core::FlowTracker tracker(globals.syn_threshold, globals.syn_window, globals.auto_block,
                              globals.auto_block_ttl);
    core::FlowStateSnapshot flow_snapshot;

    bpf::RingBuf ringbuf;
    auto rb_cb = [&globals, &tracker](const kwatch_event &e) {
        tracker.process_event(e);
        const auto line = core::format_event(
            e, globals.json ? core::EventOutputFormat::Json : core::EventOutputFormat::Text,
            get_rfc3339_time());
        (void)std::fprintf(stdout, "%s\n", line.c_str());
        std::fflush(stdout);
    };

    if (!ringbuf.init(bpf_map__fd(skel->get()->maps.events), rb_cb).is_ok()) {
        return 125;
    }

    util::UniqueFd epoll_fd(epoll_create1(0));
    if (!epoll_fd.is_valid())
        return 125;

    struct epoll_event ev_sig = {EPOLLIN, {.fd = sigs.get_fd()}};
    struct epoll_event ev_tick = {EPOLLIN, {.fd = tick.get_fd()}};
    struct epoll_event ev_rb = {EPOLLIN, {.fd = ringbuf.get_fd()}};

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sigs.get_fd(), &ev_sig);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tick.get_fd(), &ev_tick);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ringbuf.get_fd(), &ev_rb);

    LOG_INFO("run", "Running on " + if_name + ". Press Ctrl+C to stop.");

    int blacklist_fd = bpf_map__fd(skel->get()->maps.blacklist);
    int flow_state_fd = bpf_map__fd(skel->get()->maps.flow_state);
    bool running = true;

    while (running) {
        struct epoll_event ep_events[3];
        int n = epoll_wait(epoll_fd, ep_events, 3, -1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            break;

        for (int i = 0; i < n; i++) {
            if (ep_events[i].data.fd == sigs.get_fd()) {
                int sig = sigs.read_signal();
                if (sig == SIGINT || sig == SIGTERM) {
                    LOG_INFO("run", "Termination signal received, exiting...");
                    running = false;
                    break;
                }
                if (sig == SIGSEGV || sig == SIGABRT || sig == SIGILL || sig == SIGFPE) {
                    LOG_ERROR("run", "Crash signal received, exiting through RAII cleanup");
                    running = false;
                    break;
                }
            } else if (ep_events[i].data.fd == ringbuf.get_fd()) {
                ringbuf.consume(1024);
            } else if (ep_events[i].data.fd == tick.get_fd()) {
                tick.consume();

                uint64_t now_ns = get_time_ns();
                auto snapshot_res = flow_snapshot.refresh(flow_state_fd);
                if (snapshot_res.is_ok()) {
                    tracker.process_flow_snapshot(flow_snapshot.entries(), now_ns);
                } else {
                    LOG_WARN("run", snapshot_res.error());
                }

                const auto &to_block = tracker.tick_and_get_blocks(now_ns);
                const auto &to_unblock = tracker.get_expired_blocks(now_ns);

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
