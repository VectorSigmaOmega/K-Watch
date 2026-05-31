#pragma once
#include <unistd.h>
#include <utility>

namespace util {

/**
 * RAII wrapper for file descriptors.
 */
class UniqueFd {
    int fd;

    static bool is_open_fd(int value) { return value >= 0; }

  public:
    explicit UniqueFd(int f = -1) : fd(f) {}
    ~UniqueFd() {
        if (is_open_fd(fd)) {
            close(fd);
        }
    }

    // No copy
    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    // Move
    UniqueFd(UniqueFd &&other) noexcept : fd(other.fd) { other.fd = -1; }
    UniqueFd &operator=(UniqueFd &&other) noexcept {
        if (this != &other) {
            if (is_open_fd(fd))
                close(fd);
            fd = other.fd;
            other.fd = -1;
        }
        return *this;
    }

    int get() const { return fd; }
    operator int() const { return fd; }
    bool is_valid() const { return is_open_fd(fd); }

    void reset(int f = -1) {
        if (is_open_fd(fd))
            close(fd);
        fd = f;
    }

    int release() {
        int f = fd;
        fd = -1;
        return f;
    }
};

} // namespace util
