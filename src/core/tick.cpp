#include "tick.h"
#include <sys/timerfd.h>
#include <unistd.h>
#include <cstdint>

namespace core {

TickTimer::TickTimer() : tfd(-1) {}
TickTimer::~TickTimer() {
    if (tfd != -1) close(tfd);
}

util::Result<void> TickTimer::init(int hz) {
    if (hz <= 0) return util::Result<void>::Err("Invalid hz");

    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd == -1) return util::Result<void>::Err("timerfd_create failed");

    long long interval_ns = 1000000000LL / hz;
    struct itimerspec its = {};
    its.it_value.tv_sec = interval_ns / 1000000000;
    its.it_value.tv_nsec = interval_ns % 1000000000;
    its.it_interval = its.it_value;

    if (timerfd_settime(tfd, 0, &its, NULL) == -1) {
        close(tfd);
        tfd = -1;
        return util::Result<void>::Err("timerfd_settime failed");
    }

    return util::Result<void>::Ok();
}

void TickTimer::consume() {
    uint64_t expirations;
    ssize_t s = read(tfd, &expirations, sizeof(expirations));
    (void)s;
}

} // namespace core