#include "skeleton.h"
#include "../log/log.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace bpf {

static std::string libbpf_err_buf;
static int capture_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_WARN || level == LIBBPF_DEBUG) {
        char buf[1024];
        vsnprintf(buf, sizeof(buf), format, args);
        if (libbpf_err_buf.size() < 4096U) {
            libbpf_err_buf += buf;
        }
    }
    return 0;
}

static std::string one_line_libbpf_details() {
    std::string details;
    details.reserve(libbpf_err_buf.size());
    bool last_was_space = false;
    for (char ch : libbpf_err_buf) {
        const bool whitespace = ch == '\n' || ch == '\r' || ch == '\t';
        if (whitespace || ch == ' ') {
            if (!last_was_space) {
                details += ' ';
                last_was_space = true;
            }
            continue;
        }
        details += ch;
        last_was_space = false;
    }
    if (details.size() > 1000U) {
        details.resize(1000U);
        details += "...";
    }
    return details;
}

Skeleton::Skeleton(struct kwatch_bpf *s) : skel(s) {}

Skeleton::~Skeleton() {
    if (skel) {
        if (!pinned_path.empty()) {
            unpin(pinned_path);
        }
        kwatch_bpf__destroy(skel);
        skel = nullptr;
    }
}

Skeleton::Skeleton(Skeleton &&other) noexcept
    : skel(other.skel), pinned_path(std::move(other.pinned_path)) {
    other.skel = nullptr;
    other.pinned_path.clear();
}

Skeleton &Skeleton::operator=(Skeleton &&other) noexcept {
    if (this != &other) {
        if (skel) {
            if (!pinned_path.empty()) {
                unpin(pinned_path);
            }
            kwatch_bpf__destroy(skel);
        }
        skel = other.skel;
        pinned_path = std::move(other.pinned_path);
        other.skel = nullptr;
        other.pinned_path.clear();
    }
    return *this;
}

util::Result<std::unique_ptr<Skeleton>> Skeleton::open_and_load(int *err_out, uint32_t sample_n,
                                                                uint32_t syn_window_s) {
    if (err_out)
        *err_out = 0;
    libbpf_err_buf.clear();
    libbpf_set_print(capture_libbpf_log);

    struct kwatch_bpf *s = kwatch_bpf__open();
    if (!s) {
        int e = errno ? errno : EIO;
        if (err_out)
            *err_out = e;
        std::string err = "Failed to open BPF skeleton: " + std::string(strerror(e));
        LOG_ERROR("bpf", err);
        kwlog::init_libbpf_logging();
        return util::Result<std::unique_ptr<Skeleton>>::Err("open failed");
    }

    if (s->rodata) {
        s->rodata->sample_n = sample_n;
        s->rodata->syn_window_ns = static_cast<unsigned long long>(syn_window_s) * 1000000000ULL;
    }

    int err = kwatch_bpf__load(s);
    if (err) {
        // libbpf returns negative errno; translate into a positive errno.
        int e = -err;
        if (e <= 0)
            e = EIO;
        if (err_out)
            *err_out = e;
        if (e != EPERM && e != EACCES) {
            std::string msg = "Failed to load BPF skeleton: " + std::string(strerror(e));
            if (!libbpf_err_buf.empty()) {
                msg += " details=" + one_line_libbpf_details();
            }
            LOG_ERROR("bpf", msg);
        }
        kwatch_bpf__destroy(s);
        kwlog::init_libbpf_logging();
        return util::Result<std::unique_ptr<Skeleton>>::Err("load failed");
    }

    kwlog::init_libbpf_logging();
    return util::Result<std::unique_ptr<Skeleton>>::Ok(std::unique_ptr<Skeleton>(new Skeleton(s)));
}

util::Result<void> Skeleton::pin(const std::string &path) {
    if (!skel)
        return util::Result<void>::Err("Skeleton is null");

    if (mkdir(path.c_str(), 0755) != 0) {
        if (errno != EEXIST) {
            LOG_ERROR("bpf", "Failed to create pin directory " + path + ": " +
                                 std::string(strerror(errno)));
            return util::Result<void>::Err("mkdir failed");
        }
        struct stat st;
        if (stat(path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
            LOG_ERROR("bpf", "Pin path " + path + " exists but is not a directory");
            return util::Result<void>::Err("pin path is not a directory");
        }
    }

    bpf_object__unpin_maps(skel->obj, path.c_str());

    int err = bpf_object__pin_maps(skel->obj, path.c_str());
    if (err) {
        LOG_ERROR("bpf", "Failed to pin maps to " + path + ": " + std::string(strerror(-err)));
        return util::Result<void>::Err("pin failed");
    }
    pinned_path = path;
    return util::Result<void>::Ok();
}

void Skeleton::unpin(const std::string &path) {
    if (skel) {
        bpf_object__unpin_maps(skel->obj, path.c_str());
        rmdir(path.c_str());
    }
    if (pinned_path == path) {
        pinned_path.clear();
    }
}

} // namespace bpf
