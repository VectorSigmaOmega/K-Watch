#include "skeleton.h"
#include "../log/log.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <cerrno>
#include <cstring>
#include <string>
#include <cstdarg>

namespace bpf {

static std::string libbpf_err_buf;
static int capture_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_WARN || level == LIBBPF_DEBUG) { // DEBUG often contains the specific field info
        char buf[1024];
        vsnprintf(buf, sizeof(buf), format, args);
        libbpf_err_buf += buf;
    }
    return 0;
}

Skeleton::Skeleton(struct kwatch_bpf* s) : skel(s) {}

Skeleton::~Skeleton() {
    if (skel) {
        kwatch_bpf__destroy(skel);
        skel = nullptr;
    }
}

Skeleton::Skeleton(Skeleton&& other) noexcept : skel(other.skel) {
    other.skel = nullptr;
}

Skeleton& Skeleton::operator=(Skeleton&& other) noexcept {
    if (this != &other) {
        if (skel) kwatch_bpf__destroy(skel);
        skel = other.skel;
        other.skel = nullptr;
    }
    return *this;
}

util::Result<std::unique_ptr<Skeleton>> Skeleton::open_and_load() {
    libbpf_err_buf.clear();
    libbpf_set_print(capture_libbpf_log);

    struct kwatch_bpf* s = kwatch_bpf__open();
    if (!s) {
        std::string err = "Failed to open BPF skeleton: " + std::string(strerror(errno));
        LOG_ERROR("bpf", err);
        libbpf_set_print(NULL);
        return util::Result<std::unique_ptr<Skeleton>>::Err("open failed");
    }

    int err = kwatch_bpf__load(s);
    if (err) {
        std::string msg = "Failed to load BPF skeleton: " + std::string(strerror(-err));
        if (!libbpf_err_buf.empty()) {
            msg += " Details: " + libbpf_err_buf;
        }
        LOG_ERROR("bpf", msg);
        kwatch_bpf__destroy(s);
        libbpf_set_print(NULL);
        return util::Result<std::unique_ptr<Skeleton>>::Err("load failed");
    }

    libbpf_set_print(NULL);
    return util::Result<std::unique_ptr<Skeleton>>::Ok(std::unique_ptr<Skeleton>(new Skeleton(s)));
}

#include <sys/stat.h>
#include <unistd.h>

util::Result<void> Skeleton::pin(const std::string& path) {
    if (!skel) return util::Result<void>::Err("Skeleton is null");
    
    mkdir(path.c_str(), 0755); 
    bpf_object__unpin_maps(skel->obj, path.c_str()); 
    
    int err = bpf_object__pin_maps(skel->obj, path.c_str());
    if (err) {
        LOG_ERROR("bpf", "Failed to pin maps to " + path + ": " + std::string(strerror(-err)));
        return util::Result<void>::Err("pin failed");
    }
    return util::Result<void>::Ok();
}

void Skeleton::unpin(const std::string& path) {
    if (skel) {
        bpf_object__unpin_maps(skel->obj, path.c_str());
        rmdir(path.c_str());
    }
}

} // namespace bpf