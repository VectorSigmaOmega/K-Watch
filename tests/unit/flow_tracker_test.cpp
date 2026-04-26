#include "../vendored/doctest.h"
#include "../../src/core/flow_tracker.h"

TEST_CASE("FlowTracker Basic") {
    core::FlowTracker tracker(2, 10, true, 300);

    kwatch_event e1 = {1000000000ULL, 0x01010101, 0, 0, 0, 6, 0x02, 64, 0}; // SYN from IP 1
    tracker.process_event(e1);

    auto blocks = tracker.tick_and_get_blocks(1000000000ULL);
    CHECK(blocks.empty());

    kwatch_event e2 = {2000000000ULL, 0x01010101, 0, 0, 0, 6, 0x02, 64, 0}; // SYN from IP 1
    tracker.process_event(e2);

    blocks = tracker.tick_and_get_blocks(2000000000ULL);
    REQUIRE(blocks.size() == 1);
    CHECK(blocks[0] == 0x01010101);

    auto unblocks = tracker.get_expired_blocks(2000000000ULL);
    CHECK(unblocks.empty());

    unblocks = tracker.get_expired_blocks(302000000000ULL); // 300s later
    REQUIRE(unblocks.size() == 1);
    CHECK(unblocks[0] == 0x01010101);
}

TEST_CASE("FlowTracker ACK mitigates SYN") {
    core::FlowTracker tracker(2, 10, true, 300);

    kwatch_event e1 = {1000000000ULL, 0x01010101, 0, 0, 0, 6, 0x02, 64, 0}; // SYN
    kwatch_event e2 = {2000000000ULL, 0x01010101, 0, 0, 0, 6, 0x10, 64, 0}; // ACK
    kwatch_event e3 = {3000000000ULL, 0x01010101, 0, 0, 0, 6, 0x02, 64, 0}; // SYN

    tracker.process_event(e1);
    tracker.process_event(e2);
    tracker.process_event(e3);

    auto blocks = tracker.tick_and_get_blocks(3000000000ULL);
    CHECK(blocks.empty()); // 2 SYNs but 1 ACK -> not purely SYN without ACK
}