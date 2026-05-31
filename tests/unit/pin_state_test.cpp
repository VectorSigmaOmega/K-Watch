#include "../../src/bpf/pin_state.h"
#include "../vendored/doctest.h"

#include <unistd.h>

TEST_CASE("Owner state validates the current process identity") {
    auto owner = bpf::current_owner_state();
    REQUIRE(owner.is_ok());
    CHECK(owner.value().pid == static_cast<int>(getpid()));
    CHECK(bpf::is_owner_alive(owner.value()));

    bpf::OwnerState stale = owner.value();
    stale.start_time_ticks += 1U;
    CHECK_FALSE(bpf::is_owner_alive(stale));
}
