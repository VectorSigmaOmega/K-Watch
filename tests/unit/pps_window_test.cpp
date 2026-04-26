#include "../vendored/doctest.h"
#include "../../src/core/pps_window.h"

TEST_CASE("PPS Window Basic") {
    core::PpsWindow win(3);
    
    auto snap1 = win.get_snapshot();
    CHECK(snap1.empty());
    CHECK(win.current_average() == 0);

    win.push(10);
    win.push(20);
    
    auto snap2 = win.get_snapshot();
    CHECK(snap2.size() == 2);
    CHECK(snap2[0] == 10);
    CHECK(snap2[1] == 20);
    CHECK(win.current_average() == 15);

    win.push(30);
    win.push(40); // Overwrites 10

    auto snap3 = win.get_snapshot();
    CHECK(snap3.size() == 3);
    CHECK(snap3[0] == 20);
    CHECK(snap3[1] == 30);
    CHECK(snap3[2] == 40);
    CHECK(win.current_average() == 30);
}