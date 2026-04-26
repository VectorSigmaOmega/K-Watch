#pragma once
#include <sys/signalfd.h>
#include <signal.h>
#include "result.h"
#include "fd.h"

namespace util {

class SignalHandler {
    UniqueFd sfd;

public:
    SignalHandler() = default;
    
    // Initializes signalfd for SIGINT and SIGTERM.
    // Also sets up a minimal emergency handler for SIGSEGV/SIGABRT/SIGILL/SIGFPE.
    Result<void> init();

    int get_fd() const { return sfd.get(); }

    // Reads the signal from the fd and returns it.
    int read_signal();

    // Static cleanup for crash handler (minimal possible work)
    static void set_emergency_iface(const std::string& iface, int ifindex);
};

} // namespace util