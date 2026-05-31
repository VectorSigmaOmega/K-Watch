#include "skeleton.h"
#include "../../bpf/kwatch_shared.h"
#include "../log/log.h"
#include "pin_state.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <dirent.h>
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

static bool directory_is_empty(const std::string &path) {
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        return true;
    }

    bool empty = true;
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        empty = false;
        break;
    }

    closedir(dir);
    return empty;
}

static std::string parent_dir(const std::string &path) {
    const std::string::size_type slash = path.rfind('/');
    if (slash == std::string::npos) {
        return {};
    }
    return path.substr(0, slash);
}

static util::Result<void> ensure_dir(const std::string &path) {
    if (mkdir(path.c_str(), 0755) == 0) {
        return util::Result<void>::Ok();
    }
    if (errno != EEXIST) {
        return util::Result<void>::Err("mkdir failed");
    }

    struct stat st {};
    if (stat(path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        return util::Result<void>::Err("path is not a directory");
    }
    return util::Result<void>::Ok();
}

static util::Result<void> ensure_owner_pid_parent(const std::string &owner_pid_path) {
    auto root = ensure_dir("/run/kwatch");
    if (!root.is_ok()) {
        return root;
    }

    const std::string owner_dir = parent_dir(owner_pid_path);
    if (owner_dir.empty()) {
        return util::Result<void>::Err("owner state dir missing");
    }
    return ensure_dir(owner_dir);
}

static util::Result<void> write_owner_pid_file(const std::string &owner_pid_path) {
    auto owner = current_owner_state();
    if (!owner.is_ok()) {
        return util::Result<void>::Err(owner.error());
    }

    FILE *fp = std::fopen(owner_pid_path.c_str(), "w");
    if (fp == nullptr) {
        return util::Result<void>::Err("owner file open failed");
    }
    if (std::fprintf(fp, "%d %llu\n", owner.value().pid,
                     static_cast<unsigned long long>(owner.value().start_time_ticks)) < 0) {
        std::fclose(fp);
        unlink(owner_pid_path.c_str());
        return util::Result<void>::Err("owner file write failed");
    }
    if (std::fclose(fp) != 0) {
        unlink(owner_pid_path.c_str());
        return util::Result<void>::Err("owner file close failed");
    }
    return util::Result<void>::Ok();
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
    : skel(other.skel), pinned_path(std::move(other.pinned_path)),
      owner_pid_path(std::move(other.owner_pid_path)) {
    other.skel = nullptr;
    other.pinned_path.clear();
    other.owner_pid_path.clear();
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
        owner_pid_path = std::move(other.owner_pid_path);
        other.skel = nullptr;
        other.pinned_path.clear();
        other.owner_pid_path.clear();
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
        const kwatch_runtime_config cfg = kwatch_make_runtime_config(sample_n, syn_window_s);
        s->rodata->sample_n = cfg.sample_n;
        s->rodata->syn_window_ns = cfg.syn_window_ns;
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

util::Result<void> Skeleton::pin(const std::string &path, const std::string &owner_pid_file) {
    if (!skel)
        return util::Result<void>::Err("Skeleton is null");

    bool created_dir = false;
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
    } else {
        created_dir = true;
    }

    auto owner = read_owner_state(owner_pid_file);
    if (owner.is_ok()) {
        if (is_owner_alive(owner.value())) {
            LOG_ERROR("bpf", "Pin path " + path + " is owned by active pid " +
                                 std::to_string(static_cast<long>(owner.value().pid)));
            if (created_dir) {
                rmdir(path.c_str());
            }
            return util::Result<void>::Err("active owner exists");
        }
        LOG_WARN("bpf", "Reclaiming stale pin path " + path);
        bpf_object__unpin_maps(skel->obj, path.c_str());
        unlink(owner_pid_file.c_str());
    } else if (!directory_is_empty(path)) {
        LOG_WARN("bpf", "Reclaiming unowned pin path " + path);
        bpf_object__unpin_maps(skel->obj, path.c_str());
    }

    int err = bpf_object__pin_maps(skel->obj, path.c_str());
    if (err) {
        LOG_ERROR("bpf", "Failed to pin maps to " + path + ": " + std::string(strerror(-err)));
        if (created_dir && directory_is_empty(path)) {
            rmdir(path.c_str());
        }
        return util::Result<void>::Err("pin failed");
    }

    auto owner_dir = ensure_owner_pid_parent(owner_pid_file);
    if (!owner_dir.is_ok()) {
        bpf_object__unpin_maps(skel->obj, path.c_str());
        if (created_dir && directory_is_empty(path)) {
            rmdir(path.c_str());
        }
        LOG_ERROR("bpf",
                  "Failed to prepare owner state dir for " + path + ": " + owner_dir.error());
        return util::Result<void>::Err(owner_dir.error());
    }

    auto owner_file = write_owner_pid_file(owner_pid_file);
    if (!owner_file.is_ok()) {
        bpf_object__unpin_maps(skel->obj, path.c_str());
        if (created_dir && directory_is_empty(path)) {
            rmdir(path.c_str());
        }
        LOG_ERROR("bpf", "Failed to write owner pid for " + path);
        return util::Result<void>::Err(owner_file.error());
    }
    pinned_path = path;
    owner_pid_path = owner_pid_file;
    return util::Result<void>::Ok();
}

void Skeleton::unpin(const std::string &path) {
    if (skel) {
        bpf_object__unpin_maps(skel->obj, path.c_str());
        if (!owner_pid_path.empty()) {
            unlink(owner_pid_path.c_str());
            const std::string owner_state_dir = parent_dir(owner_pid_path);
            if (!owner_state_dir.empty()) {
                rmdir(owner_state_dir.c_str());
            }
        }
        rmdir(path.c_str());
    }
    if (pinned_path == path) {
        pinned_path.clear();
        owner_pid_path.clear();
    }
}

} // namespace bpf
