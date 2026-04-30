#include "../vendored/doctest.h"

#include <array>
#include <span>

#include "../../src/core/event_formatter.h"

TEST_CASE("Event formatter parses and renders ring buffer events") {
    kwatch_event event{};
    event.ts_ns = 123456789ULL;
    event.src_ip = 0x0100007F; // 127.0.0.1
    event.dst_ip = 0x0200007F; // 127.0.0.2
    event.sport = 1234;
    event.dport = 80;
    event.protocol = 6;
    event.tcp_flags = 0x12;
    event.ttl = 64;
    event.action = 0;
    event.icmp_type = 0;
    event.icmp_code = 0;

    std::array<uint8_t, sizeof(kwatch_event)> bytes{};
    std::memcpy(bytes.data(), &event, sizeof(event));

    auto rendered =
        core::parse_and_format_event(std::span<const uint8_t>(bytes.data(), bytes.size()),
                                     core::EventOutputFormat::Json, "2026-01-01T00:00:00Z");
    REQUIRE(rendered.is_ok());
    CHECK(rendered.value().find("\"src_ip\":\"127.0.0.1\"") != std::string::npos);
    CHECK(rendered.value().find("\"tcp_flags\":18") != std::string::npos);
    CHECK(rendered.value().find("\"icmp_type\":0") != std::string::npos);
}

TEST_CASE("Event formatter includes ICMP type and code") {
    kwatch_event event{};
    event.ts_ns = 123456789ULL;
    event.src_ip = 0x0100007F;
    event.dst_ip = 0x0200007F;
    event.protocol = 1;
    event.ttl = 64;
    event.icmp_type = 8;
    event.icmp_code = 0;

    auto rendered =
        core::format_event(event, core::EventOutputFormat::Text, "2026-01-01T00:00:00Z");
    CHECK(rendered.find("type=8") != std::string::npos);
    CHECK(rendered.find("code=0") != std::string::npos);
}

TEST_CASE("Event formatter rejects truncated buffers") {
    const std::array<uint8_t, 4> bytes{{0, 1, 2, 3}};
    auto rendered =
        core::parse_and_format_event(std::span<const uint8_t>(bytes.data(), bytes.size()),
                                     core::EventOutputFormat::Text, "2026-01-01T00:00:00Z");
    CHECK(!rendered.is_ok());
}
