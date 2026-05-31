#include "../../bpf/attach.h"
#include "../../bpf/pin_state.h"
#include "../../bpf/ringbuf.h"
#include "../../bpf/skeleton.h"
#include "../../core/event_formatter.h"
#include "../../core/tick.h"
#include "../../log/log.h"
#include "../../util/fd.h"
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

namespace {

constexpr uint32_t kDefaultSynWindowSeconds = 10;

#ifdef KWATCH_WITH_EXPERIMENTAL
struct lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};
#endif

} // namespace

static std::string get_rfc3339_time() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::tm tm_buf{};
    gmtime_r(&in_time_t, &tm_buf);
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf);
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
    auto skel_res =
        bpf::Skeleton::open_and_load(&load_err, globals.sample_n, kDefaultSynWindowSeconds);
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

    std::string pin_path = bpf::pin_path_for_iface(if_name);
    std::string owner_pid_path = bpf::owner_pid_path_for_iface(if_name);
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
    LOG_INFO("run", "Attached XDP on " + if_name + " (mode=" + attach_res.value() + ")");

    util::SignalHandler sigs;
    if (!sigs.init().is_ok())
        return 125;

    core::TickTimer tick;
    if (!tick.init(2).is_ok())
        return 125; // 2 Hz

    bpf::RingBuf ringbuf;
    auto rb_cb = [&globals](const kwatch_event &e) {
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
            } else if (ep_events[i].data.fd == ringbuf.get_fd()) {
                ringbuf.consume(1024);
            } else if (ep_events[i].data.fd == tick.get_fd()) {
                tick.consume();
            }
        }
    }

    skel->unpin(pin_path);
    return 0;
}

} // namespace cli
