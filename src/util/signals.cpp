#include "signals.h"
#include <unistd.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <iostream>

namespace util {

Result<void> SignalHandler::init() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    // Block signals so they aren't handled by default handlers,
    // but instead are delivered via signalfd.
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
    return fdsi.ssi_signo;
}

} // namespace util