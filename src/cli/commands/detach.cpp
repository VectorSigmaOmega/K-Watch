#include "../../bpf/pin_state.h"
#include "../../log/log.h"
#include "../parser.h"
#include <array>
#include <bpf/libbpf.h>
#if __has_include(<bpf/libbpf_version.h>)
#include <bpf/libbpf_version.h>
#endif
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <net/if.h>
#include <unistd.h>

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif
#ifndef XDP_FLAGS_HW_MODE
#define XDP_FLAGS_HW_MODE (1U << 3)
#endif

namespace cli {

static bool is_ignorable_detach_error(int err) {
    return err == EINVAL || err == ENOENT || err == ENODEV || err == EOPNOTSUPP || err == ENOLINK;
}

static int detach_xdp(int if_index, unsigned int flags) {
#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION > 0 || LIBBPF_MINOR_VERSION >= 7)
    return bpf_xdp_detach(if_index, flags, nullptr);
#else
    return bpf_set_link_xdp_fd(if_index, -1, flags);
#endif
}

static bool wait_for_owner_exit(const bpf::OwnerState &owner, useconds_t timeout_us) {
    constexpr useconds_t step_us = 100000;
    useconds_t waited = 0;
    while (waited < timeout_us) {
        if (!bpf::is_owner_alive(owner)) {
            return true;
        }
        usleep(step_us);
        waited += step_us;
    }
    return !bpf::is_owner_alive(owner);
}

static util::Result<bool> stop_owner_process(const std::string &if_name,
                                             const bpf::OwnerState &owner) {
    if (!bpf::is_owner_alive(owner)) {
        return util::Result<bool>::Ok(false);
    }

    if (kill(owner.pid, SIGTERM) != 0) {
        if (errno == ESRCH) {
            return util::Result<bool>::Ok(false);
        }
        if (errno == EPERM || errno == EACCES) {
            return util::Result<bool>::Err("permission");
        }
        return util::Result<bool>::Err("signal failed");
    }

    if (wait_for_owner_exit(owner, 2000000)) {
        LOG_INFO("detach",
                 "Stopped kwatch owner pid " + std::to_string(owner.pid) + " on " + if_name);
        return util::Result<bool>::Ok(true);
    }

    LOG_WARN("detach", "Owner pid " + std::to_string(owner.pid) +
                           " did not exit after SIGTERM; sending SIGKILL");
    if (kill(owner.pid, SIGKILL) != 0 && errno != ESRCH) {
        if (errno == EPERM || errno == EACCES) {
            return util::Result<bool>::Err("permission");
        }
        return util::Result<bool>::Err("signal failed");
    }
    if (!wait_for_owner_exit(owner, 1000000)) {
        return util::Result<bool>::Err("owner still alive");
    }

    LOG_INFO("detach",
             "Force-stopped kwatch owner pid " + std::to_string(owner.pid) + " on " + if_name);
    return util::Result<bool>::Ok(true);
}

int cmd_detach(const GlobalOptions &globals, const std::vector<std::string> &args) {
    (void)globals;
    if (args.size() != 1) {
        std::fputs("Usage: kwatch detach <iface>\n", stderr);
        return 64;
    }
    std::string if_name = args[0];
    unsigned int raw_if_index = if_nametoindex(if_name.c_str());
    if (raw_if_index == 0) {
        LOG_ERROR("detach", "Failed to get index for interface " + if_name);
        return 65;
    }
    int if_index = static_cast<int>(raw_if_index);

    bool stopped_owner = false;
    auto owner = bpf::read_owner_state(bpf::owner_pid_path_for_iface(if_name));
    if (owner.is_ok()) {
        auto stop_res = stop_owner_process(if_name, owner.value());
        if (!stop_res.is_ok()) {
            if (stop_res.error() == "permission") {
                LOG_ERROR("detach", "Permission denied stopping kwatch owner on " + if_name +
                                        ". Need root or CAP_NET_ADMIN.");
                return 77;
            }
            LOG_ERROR("detach", "Failed stopping kwatch owner on " + if_name);
            return 69;
        }
        stopped_owner = stop_res.value();
    }

    auto cleanup_res = bpf::cleanup_stale_state(if_name);
    if (!cleanup_res.is_ok()) {
        if (cleanup_res.error() == "active owner exists") {
            LOG_ERROR("detach",
                      "kwatch owner on " + if_name + " is still active after stop attempt");
        } else {
            LOG_ERROR("detach", "Failed cleaning stale kwatch state on " + if_name);
        }
        return 69;
    }

    const std::array<unsigned int, 4> flags = {
        XDP_FLAGS_HW_MODE,
        XDP_FLAGS_DRV_MODE,
        XDP_FLAGS_SKB_MODE,
        0U,
    };
    bool detached = false;
    int first_error = 0;

    for (unsigned int flag : flags) {
        const int ret = detach_xdp(if_index, flag);
        if (ret == 0) {
            detached = true;
            continue;
        }

        const int err = -ret;
        if (err == EPERM || err == EACCES) {
            LOG_ERROR("detach", "Permission denied detaching XDP from " + if_name +
                                    ". Need root or CAP_NET_ADMIN.");
            return 77;
        }
        if (!is_ignorable_detach_error(err) && first_error == 0) {
            first_error = err;
        }
    }

    if (first_error != 0) {
        LOG_ERROR("detach", "Failed detaching XDP from " + if_name + ": " +
                                std::string(std::strerror(first_error)));
        return 69;
    }

    if (stopped_owner) {
        LOG_INFO("detach", "Stopped kwatch owner and detached XDP from " + if_name);
    } else if (detached) {
        LOG_INFO("detach", "Detached legacy XDP attachment from " + if_name);
    } else if (cleanup_res.value()) {
        LOG_INFO("detach", "Cleaned stale kwatch state for " + if_name);
    } else {
        LOG_INFO("detach", "No kwatch XDP state attached to " + if_name);
    }
    return 0;
}

} // namespace cli
