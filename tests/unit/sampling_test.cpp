#include "../../bpf/kwatch_shared.h"
#include "../vendored/doctest.h"

TEST_CASE("Sampling runtime config encodes sample_n and syn window") {
    const kwatch_runtime_config cfg = kwatch_make_runtime_config(8, 7);
    CHECK(cfg.sample_n == 8U);
    CHECK(cfg.syn_window_ns == 7000000000ULL);
}

TEST_CASE("Sampling emits the first packet of a flow") {
    CHECK(kwatch_should_emit_event(100U, 99U, true));
}

TEST_CASE("Sampling emits every packet when sample_n is one") {
    CHECK(kwatch_should_emit_event(1U, 0U, false));
    CHECK(kwatch_should_emit_event(1U, 99U, false));
}

TEST_CASE("Sampling emits one in N existing-flow packets") {
    CHECK(kwatch_should_emit_event(4U, 8U, false));
    CHECK_FALSE(kwatch_should_emit_event(4U, 9U, false));
}
