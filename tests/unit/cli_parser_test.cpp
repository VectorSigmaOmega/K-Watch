#include "../vendored/doctest.h"
#include "../../src/cli/parser.h"

TEST_CASE("CLI Parser") {
    SUBCASE("No command") {
        char* argv[] = {(char*)"kwatch"};
        auto res = cli::parse_args(1, argv);
        CHECK(!res.is_ok());
    }

    SUBCASE("Basic run command") {
        char* argv[] = {(char*)"kwatch", (char*)"run", (char*)"eth0"};
        auto res = cli::parse_args(3, argv);
        REQUIRE(res.is_ok());
        CHECK(res.value().cmd == cli::Command::Run);
        REQUIRE(res.value().args.size() == 1);
        CHECK(res.value().args[0] == "eth0");
        CHECK(res.value().globals.json == false);
    }

    SUBCASE("Global options and command") {
        char* argv[] = {(char*)"kwatch", (char*)"--json", (char*)"-v", (char*)"--xdp-mode", (char*)"skb", (char*)"block", (char*)"1.1.1.1"};
        auto res = cli::parse_args(7, argv);
        REQUIRE(res.is_ok());
        CHECK(res.value().cmd == cli::Command::Block);
        CHECK(res.value().globals.json == true);
        CHECK(res.value().globals.verbose == 1);
        CHECK(res.value().globals.xdp_mode == "skb");
        REQUIRE(res.value().args.size() == 1);
        CHECK(res.value().args[0] == "1.1.1.1");
    }

    SUBCASE("Invalid global option") {
        char* argv[] = {(char*)"kwatch", (char*)"--unknown", (char*)"run"};
        auto res = cli::parse_args(3, argv);
        CHECK(!res.is_ok());
    }
}