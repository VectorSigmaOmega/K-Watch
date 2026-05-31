#include "../../src/util/ipv4.h"
#include "../vendored/doctest.h"

TEST_CASE("IPv4 Parsing") {
    auto res = util::ipv4::parse("192.168.1.1");
    CHECK(res.is_ok());
    CHECK(res.value() == 0x0101A8C0); // 192.168.1.1 in network byte order

    auto res2 = util::ipv4::parse("invalid");
    CHECK(!res2.is_ok());
}

TEST_CASE("CIDR Parsing") {
    auto res = util::ipv4::parse_cidr("10.0.0.0/8");
    CHECK(res.is_ok());
    CHECK(res.value().first == 0x0000000A);
    CHECK(res.value().second == 8);

    auto res_no_slash = util::ipv4::parse_cidr("10.0.0.1");
    CHECK(res_no_slash.is_ok());
    CHECK(res_no_slash.value().first == 0x0100000A);
    CHECK(res_no_slash.value().second == 32);

    auto res_invalid = util::ipv4::parse_cidr("10.0.0.0/33");
    CHECK(!res_invalid.is_ok());

    auto res_trailing = util::ipv4::parse_cidr("10.0.0.0/8junk");
    CHECK(!res_trailing.is_ok());

    auto res_missing_prefix = util::ipv4::parse_cidr("10.0.0.0/");
    CHECK(!res_missing_prefix.is_ok());
}

TEST_CASE("IPv4 Formatting") {
    std::string ip = util::ipv4::format(0x0101A8C0);
    CHECK(ip == "192.168.1.1");
}
