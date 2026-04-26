#include "app.h"
#include <ncurses.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include "widgets/sparkline.h"
#include "../util/ipv4.h"
#include <bpf/bpf.h>
#include <cstring>
#include <cstdlib>
#include <signal.h>
#include "../demo/demos.h"

namespace tui {

struct lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};

static void emergency_cleanup(int sig) {
    endwin();
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigaction(sig, &sa, NULL);
    raise(sig);
}

static std::string format_tcp_flags(uint8_t flags) {
    std::string s;
    if (flags & 0x02) s += "S";
    if (flags & 0x10) s += "A";
    if (flags & 0x08) s += "P";
    if (flags & 0x01) s += "F";
    if (flags & 0x04) s += "R";
    if (s.empty()) s = "-";
    return s;
}

App::App(const std::string& i, const std::string& m, 
         const core::PpsWindow& pps_win, std::vector<kwatch_event>& events,
         std::mutex& mtx, const core::FlowTracker& tracker,
         int pkt_fd, int bl_fd)
    : iface(i), mode(m), pps_window(pps_win), recent_events(events), 
      events_mutex(mtx), flow_tracker(tracker), pkt_counts_fd(pkt_fd), blacklist_fd(bl_fd) {}

App::~App() {
    running = false;
    if (demo_thread.joinable()) demo_thread.join();
    endwin();
}

util::Result<void> App::init() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = emergency_cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);

    bool use_color = has_colors() && (std::getenv("NO_COLOR") == nullptr);
    if (use_color) {
        start_color();
        init_pair(1, COLOR_CYAN, COLOR_BLACK);   
        init_pair(2, COLOR_GREEN, COLOR_BLACK);  
        init_pair(3, COLOR_RED, COLOR_BLACK);    
        init_pair(4, COLOR_YELLOW, COLOR_BLACK); 
    }

    return util::Result<void>::Ok();
}

void App::handle_input() {
    int ch = getch();
    if (ch == 'q' || ch == 'Q') running = false;
    else if (ch == '1') current_view = View::Dashboard;
    else if (ch == '2') current_view = View::Threats;
    else if (ch == '3') current_view = View::Firewall;
    else if (ch == '4') current_view = View::Demos;
    else if (current_view == View::Demos) {
        if (ch == 's' || ch == 'S') launch_demo("syn-flood");
        else if (ch == 'p' || ch == 'P') launch_demo("ping-flood");
        else if (ch == 'u' || ch == 'U') launch_demo("udp-storm");
    }
}

void App::launch_demo(const std::string& name) {
    if (demo_thread.joinable()) demo_thread.join();
    
    demo::DemoConfig cfg;
    cfg.target_ip = "127.0.0.1"; 
    cfg.target_port = 80;
    cfg.rate_pps = 50;
    cfg.duration_s = 5;
    cfg.override_safety = false;

    demo_thread = std::thread([name, cfg]() {
        if (name == "syn-flood") demo::run_syn_flood(cfg);
        else if (name == "ping-flood") demo::run_ping_flood(cfg);
        else if (name == "udp-storm") demo::run_udp_storm(cfg);
    });
}

void App::render() {
    erase();
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    auto pps_snapshot = pps_window.get_snapshot();

    if (has_colors() && (std::getenv("NO_COLOR") == nullptr)) attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(0, 0, "kwatch %s · mode=%s · pps=%lu · [1]Dash [2]Threats [3]Firewall [4]Demo [q]Quit", 
             iface.c_str(), mode.c_str(), pps_snapshot.empty() ? 0 : pps_snapshot.back());
    if (has_colors() && (std::getenv("NO_COLOR") == nullptr)) attroff(COLOR_PAIR(1) | A_BOLD);

    switch (current_view) {
        case View::Dashboard: {
            mvprintw(2, 0, "Traffic (PPS)");
            mvprintw(3, 0, "%s", widgets::render_sparkline(pps_snapshot, max_x - 2).c_str());
            
            mvprintw(5, 0, "Recent Events");
            mvprintw(6, 0, "--------------------------------------------------------------------------------");
            std::lock_guard<std::mutex> lock(events_mutex);
            for (size_t i = 0; i < recent_events.size() && i < (size_t)(max_y - 8); ++i) {
                const auto& e = recent_events[recent_events.size() - 1 - i];
                mvprintw(7 + (int)i, 0, "%s:%d -> %s:%d flags=%s ttl=%d", 
                         util::ipv4::format(e.src_ip).c_str(), e.sport, 
                         util::ipv4::format(e.dst_ip).c_str(), e.dport, 
                         format_tcp_flags(e.tcp_flags).c_str(), (int)e.ttl);
            }
            break;
        }
        case View::Threats: {
            mvprintw(2, 0, "Threat Matrix (Top Connections)");
            mvprintw(3, 0, "--------------------------------------------------------------------------------");
            mvprintw(4, 0, "%-16s %-8s %-8s %-16s %-16s", "Source IP", "SYNs", "ACKs", "Heuristic", "Status");
            auto flows = flow_tracker.get_snapshot();
            int line = 5;
            for (auto const& [ip, stats] : flows) {
                if (line >= max_y - 1) break;
                bool flagged = stats.is_flagged;
                if (flagged && has_colors() && (std::getenv("NO_COLOR") == nullptr)) attron(COLOR_PAIR(3));
                mvprintw(line++, 0, "%-16s %-8u %-8u %-16s %-16s", 
                         util::ipv4::format(ip).c_str(), stats.syn_count, stats.ack_count, 
                         "?", 
                         flagged ? "SYN_FLOOD" : "OK");
                if (flagged && has_colors() && (std::getenv("NO_COLOR") == nullptr)) attroff(COLOR_PAIR(3));
            }
            break;
        }
        case View::Firewall: {
            mvprintw(2, 0, "Firewall (Blacklist)");
            mvprintw(3, 0, "--------------------------------------------------------------------------------");
            mvprintw(4, 0, "Prefix");
            struct lpm_key start_key = {0, 0};
            struct lpm_key next_key;
            uint8_t value;
            int line = 5;
            while (bpf_map_get_next_key(blacklist_fd, &start_key, &next_key) == 0) {
                if (line >= max_y - 1) break;
                if (bpf_map_lookup_elem(blacklist_fd, &next_key, &value) == 0) {
                    mvprintw(line++, 0, "%s/%u", util::ipv4::format(next_key.data).c_str(), next_key.prefixlen);
                }
                start_key = next_key;
            }
            break;
        }
        case View::Demos:
            mvprintw(2, 0, "Demo Scenarios (Loopback Only)");
            mvprintw(4, 0, "[s] SYN Flood (Target: 127.0.0.1)");
            mvprintw(5, 0, "[p] ICMP Ping Flood");
            mvprintw(6, 0, "[u] UDP Storm");
            mvprintw(8, 0, "Press a key to launch. Results will appear in Views 1 and 2.");
            break;
    }

    refresh();
}

} // namespace tui