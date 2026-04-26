#pragma once
#include "../util/result.h"

namespace core {

class TickTimer {
    int tfd;
public:
    TickTimer();
    ~TickTimer();

    util::Result<void> init(int hz);
    int get_fd() const { return tfd; }
    void consume();
};

} // namespace core