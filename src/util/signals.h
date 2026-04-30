#pragma once
#include "fd.h"
#include "result.h"
#include <signal.h>
#include <string>
#include <sys/signalfd.h>

namespace util {

class SignalHandler {
    UniqueFd sfd;

  public:
    SignalHandler() = default;

    // Initializes signalfd for termination and externally delivered crash signals.
    Result<void> init();

    int get_fd() const { return sfd.get(); }

    // Reads the signal from the fd and returns it.
    int read_signal();

    static void set_emergency_iface(const std::string &iface, int ifindex);
};

} // namespace util
