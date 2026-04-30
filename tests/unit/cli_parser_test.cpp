#include "../../src/cli/parser.h"
#include "../../src/demo/demos.h"
#include "../vendored/doctest.h"

TEST_CASE("CLI Parser") {
    SUBCASE("No command") {
        char *argv[] = {(char *)"kwatch"};
        auto res = cli::parse_args(1, argv);
        CHECK(!res.is_ok());
    }

    SUBCASE("Basic run command") {
        char *argv[] = {(char *)"kwatch", (char *)"run", (char *)"eth0"};
        auto res = cli::parse_args(3, argv);
        REQUIRE(res.is_ok());
        CHECK(res.value().cmd == cli::Command::Run);
        REQUIRE(res.value().args.size() == 1);
        CHECK(res.value().args[0] == "eth0");
        CHECK(res.value().globals.json == false);
    }

    SUBCASE("Global options and command") {
        char *argv[] = {(char *)"kwatch", (char *)"--json", (char *)"-v",     (char *)"--xdp-mode",
                        (char *)"skb",    (char *)"block",  (char *)"1.1.1.1"};
        auto res = cli::parse_args(7, argv);
        REQUIRE(res.is_ok());
        CHECK(res.value().cmd == cli::Command::Block);
        CHECK(res.value().globals.json == true);
        CHECK(res.value().globals.verbose == 1);
        CHECK(res.value().globals.xdp_mode == "skb");
        REQUIRE(res.value().args.size() == 1);
        CHECK(res.value().args[0] == "1.1.1.1");
    }

    SUBCASE("Global options after command are still parsed") {
        char *argv[] = {
            (char *)"kwatch",          (char *)"run", (char *)"lo",         (char *)"--json",
            (char *)"--syn-threshold", (char *)"42",  (char *)"--sample-n", (char *)"10"};
        auto res = cli::parse_args(8, argv);
        REQUIRE(res.is_ok());
        CHECK(res.value().cmd == cli::Command::Run);
        CHECK(res.value().globals.json == true);
        CHECK(res.value().globals.syn_threshold == 42);
        CHECK(res.value().globals.sample_n == 10);
        REQUIRE(res.value().args.size() == 1);
        CHECK(res.value().args[0] == "lo");
    }

    SUBCASE("Invalid numeric global option returns an error") {
        char *argv[] = {(char *)"kwatch", (char *)"--syn-threshold", (char *)"nope", (char *)"run",
                        (char *)"lo"};
        auto res = cli::parse_args(5, argv);
        CHECK(!res.is_ok());
    }

    SUBCASE("Invalid sample rate returns an error") {
        char *argv[] = {(char *)"kwatch", (char *)"--sample-n", (char *)"0", (char *)"run",
                        (char *)"lo"};
        auto res = cli::parse_args(5, argv);
        CHECK(!res.is_ok());
    }

    SUBCASE("Invalid global option") {
        char *argv[] = {(char *)"kwatch", (char *)"--unknown", (char *)"run"};
        auto res = cli::parse_args(3, argv);
        CHECK(!res.is_ok());
    }
}

TEST_CASE("Demo target validation accepts only loopback without override") {
    CHECK(demo::validate_target("127.0.0.1", false).is_ok());
    CHECK(demo::validate_target("127.42.0.9", false).is_ok());
    CHECK(!demo::validate_target("8.8.8.8", false).is_ok());
    CHECK(demo::validate_target("8.8.8.8", true).is_ok());
}
