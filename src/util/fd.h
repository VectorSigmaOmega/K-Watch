#pragma once
#include <unistd.h>
#include <utility>

namespace util {

/**
 * RAII wrapper for file descriptors.
 */
class UniqueFd {
    int fd;

public:
    explicit UniqueFd(int f = -1) : fd(f) {}
    ~UniqueFd() {
        if (fd != -1) {
            close(fd);
        }
    }

    // No copy
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    // Move
    UniqueFd(UniqueFd&& other) noexcept : fd(other.fd) {
        other.fd = -1;
    }
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            if (fd != -1) close(fd);
            fd = other.fd;
            other.fd = -1;
        }
        return *this;
    }

    int get() const { return fd; }
    operator int() const { return fd; }
    bool is_valid() const { return fd != -1; }

    void reset(int f = -1) {
        if (fd != -1) close(fd);
        fd = f;
    }

    int release() {
        int f = fd;
        fd = -1;
        return f;
    }
};

} // namespace util