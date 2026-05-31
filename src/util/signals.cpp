#include "signals.h"
#include <cstring>
#include <iostream>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

namespace util {

Result<void> SignalHandler::init() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        return Result<void>::Err("sigprocmask failed");
    }

    int fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd == -1) {
        return Result<void>::Err("signalfd failed");
    }

    sfd.reset(fd);
    return Result<void>::Ok();
}

int SignalHandler::read_signal() {
    struct signalfd_siginfo fdsi;
    ssize_t s = read(sfd.get(), &fdsi, sizeof(fdsi));
    if (s != sizeof(fdsi)) {
        return -1;
    }
    return static_cast<int>(fdsi.ssi_signo);
}

void SignalHandler::set_emergency_iface(const std::string &iface, int ifindex) {
    (void)iface;
    (void)ifindex;
}

} // namespace util
