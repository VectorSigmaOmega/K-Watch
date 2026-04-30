#include "../../src/core/flow_tracker.h"
#include "../vendored/doctest.h"

TEST_CASE("FlowTracker Basic") {
    core::FlowTracker tracker(2, 10, true, 300);

    kwatch_event e1 = {1000000000ULL, 0x01010101, 0, 0, 0, 6, 0x02, 64, 0, 0, 0};
    tracker.process_event(e1);

    std::vector<core::FlowMapEntry> snapshot(1);
    snapshot[0].key.src_ip = 0x01010101;
    snapshot[0].key.protocol = 6;
    snapshot[0].stats.syn_count = 1;
    snapshot[0].stats.ack_count = 0;
    snapshot[0].stats.last_seen_ns = 1000000000ULL;
    tracker.process_flow_snapshot(snapshot, 1000000000ULL);

    auto blocks = tracker.tick_and_get_blocks(1000000000ULL);
    CHECK(blocks.empty());

    kwatch_event e2 = {2000000000ULL, 0x01010101, 0, 0, 0, 6, 0x02, 64, 0, 0, 0};
    tracker.process_event(e2);
    snapshot[0].stats.syn_count = 2;
    snapshot[0].stats.last_seen_ns = 2000000000ULL;
    tracker.process_flow_snapshot(snapshot, 2000000000ULL);

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

    kwatch_event e1 = {1000000000ULL, 0x01010101, 0, 0, 0, 6, 0x02, 64, 0, 0, 0};
    tracker.process_event(e1);

    std::vector<core::FlowMapEntry> snapshot(1);
    snapshot[0].key.src_ip = 0x01010101;
    snapshot[0].key.protocol = 6;
    snapshot[0].stats.syn_count = 2;
    snapshot[0].stats.ack_count = 1;
    snapshot[0].stats.last_seen_ns = 3000000000ULL;
    tracker.process_flow_snapshot(snapshot, 3000000000ULL);

    auto blocks = tracker.tick_and_get_blocks(3000000000ULL);
    CHECK(blocks.empty()); // 2 SYNs but 1 ACK -> not purely SYN without ACK
}

TEST_CASE("FlowTracker ignores stale flow_state entries outside the SYN window") {
    core::FlowTracker tracker(2, 10, true, 300);

    std::vector<core::FlowMapEntry> snapshot(1);
    snapshot[0].key.src_ip = 0x01010101;
    snapshot[0].key.protocol = 6;
    snapshot[0].stats.syn_count = 100;
    snapshot[0].stats.ack_count = 0;
    snapshot[0].stats.last_seen_ns = 1000000000ULL;
    tracker.process_flow_snapshot(snapshot, 12000000000ULL);

    auto blocks = tracker.tick_and_get_blocks(12000000000ULL);
    CHECK(blocks.empty());
}

TEST_CASE("FlowTracker ignores cumulative counters from flows that started before the SYN window") {
    core::FlowTracker tracker(2, 10, true, 300);

    std::vector<core::FlowMapEntry> snapshot(1);
    snapshot[0].key.src_ip = 0x01010101;
    snapshot[0].key.protocol = 6;
    snapshot[0].stats.syn_count = 100;
    snapshot[0].stats.ack_count = 0;
    snapshot[0].stats.first_seen_ns = 1000000000ULL;
    snapshot[0].stats.last_seen_ns = 12000000000ULL;
    tracker.process_flow_snapshot(snapshot, 12000000000ULL);

    auto blocks = tracker.tick_and_get_blocks(12000000000ULL);
    CHECK(blocks.empty());
}
