#include "app.h"

#include <cstdio>
#include <cstdlib>
#include <limits>
#include <termios.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <ncurses.h>

#include "../util/ipv4.h"
#include "widgets/sparkline.h"

namespace tui {

struct lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};

static std::string format_tcp_flags(uint8_t flags) {
    std::string out;
    if ((flags & 0x02U) != 0U)
        out += "S";
    if ((flags & 0x10U) != 0U)
        out += "A";
    if ((flags & 0x08U) != 0U)
        out += "P";
    if ((flags & 0x01U) != 0U)
        out += "F";
    if ((flags & 0x04U) != 0U)
        out += "R";
    if (out.empty())
        out = "-";
    return out;
}

static const char *get_os_from_ttl(uint8_t ttl) {
    if (ttl == 64U)
        return "Linux";
    if (ttl == 128U)
        return "Windows";
    if (ttl == 255U)
        return "BSD";
    return "?";
}

static std::string format_duration(std::chrono::seconds elapsed) {
    const auto total = elapsed.count();
    const auto hours = total / 3600;
    const auto minutes = (total / 60) % 60;
    const auto seconds = total % 60;
    char buf[32];
    (void)std::snprintf(buf, sizeof(buf), "%02lld:%02lld:%02lld", static_cast<long long>(hours),
                        static_cast<long long>(minutes), static_cast<long long>(seconds));
    return std::string(buf);
}

static std::string format_ratio(uint32_t syn_count, uint32_t ack_count) {
    if (ack_count == 0U) {
        return syn_count == 0U ? "0.0" : "inf";
    }
    char buf[32];
    (void)std::snprintf(buf, sizeof(buf), "%.1f", static_cast<double>(syn_count) / ack_count);
    return std::string(buf);
}

static uint64_t protocol_total(const ProtocolBreakdown &breakdown) {
    return breakdown.tcp + breakdown.udp + breakdown.icmp + breakdown.other;
}

static uint64_t protocol_pct(uint64_t value, uint64_t total) {
    if (total == 0U)
        return 0;
    return (value * 100U) / total;
}

App::App(const std::string &iface_name, const std::string &attach_mode,
         const std::vector<uint64_t> &pps_points_ref, const uint64_t &current_pps_ref,
         std::vector<kwatch_event> &events, std::mutex &events_mutex_ref,
         const std::vector<ThreatRow> &threat_rows_ref,
         const std::vector<FirewallRow> &firewall_rows_ref,
         const ProtocolBreakdown &protocol_breakdown_ref, const uint64_t &ringbuf_error_count_ref,
         const uint64_t &event_drop_count_ref, int bl_fd)
    : iface(iface_name), mode(attach_mode), pps_points(pps_points_ref),
      current_pps(current_pps_ref), recent_events(events), events_mutex(events_mutex_ref),
      threat_rows(threat_rows_ref), firewall_rows(firewall_rows_ref),
      protocol_breakdown(protocol_breakdown_ref), ringbuf_error_count(ringbuf_error_count_ref),
      event_drop_count(event_drop_count_ref), blacklist_fd(bl_fd) {
    start_time = std::chrono::steady_clock::now();
    demo_cfg.target_ip = "127.0.0.1";
    demo_cfg.target_port = 80;
    demo_cfg.rate_pps = 50;
    demo_cfg.duration_s = 5;
    demo_cfg.override_safety = false;
}

App::~App() {
    running = false;
    if (demo_thread.joinable())
        demo_thread.join();
    endwin();
    if (termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    }
}

util::Result<void> App::init() {
    termios_saved = tcgetattr(STDIN_FILENO, &saved_termios) == 0;
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);

    color_enabled =
        isatty(STDOUT_FILENO) != 0 && has_colors() && (std::getenv("NO_COLOR") == nullptr);
    if (color_enabled) {
        start_color();
        init_pair(1, COLOR_CYAN, COLOR_BLACK);
        init_pair(2, COLOR_GREEN, COLOR_BLACK);
        init_pair(3, COLOR_RED, COLOR_BLACK);
        init_pair(4, COLOR_YELLOW, COLOR_BLACK);
    }

    return util::Result<void>::Ok();
}

static std::string prompt_input(const char *prompt) {
    echo();
    curs_set(1);
    mvprintw(LINES - 1, 0, "%s", prompt);
    clrtoeol();
    char buf[256];
    const int rc = getnstr(buf, static_cast<int>(sizeof(buf) - 1U));
    noecho();
    curs_set(0);
    if (rc == ERR) {
        return "";
    }
    return std::string(buf);
}

static bool parse_u32_input(const std::string &value, uint32_t &out) {
    if (value.empty())
        return false;

    try {
        size_t pos = 0;
        const unsigned long parsed = std::stoul(value, &pos, 10);
        if (pos != value.size() || parsed > std::numeric_limits<uint32_t>::max()) {
            return false;
        }
        out = static_cast<uint32_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

static bool parse_u16_input(const std::string &value, uint16_t &out) {
    uint32_t parsed = 0;
    if (!parse_u32_input(value, parsed) || parsed > std::numeric_limits<uint16_t>::max()) {
        return false;
    }
    out = static_cast<uint16_t>(parsed);
    return true;
}

void App::handle_input() {
    const int ch = getch();
    if (ch == 'q' || ch == 'Q') {
        running = false;
    } else if (ch == '1') {
        current_view = View::Dashboard;
    } else if (ch == '2') {
        current_view = View::Threats;
    } else if (ch == '3') {
        current_view = View::Firewall;
    } else if (ch == '4') {
        current_view = View::Demos;
    } else if (current_view == View::Firewall) {
        if (ch == KEY_UP && firewall_selected_index > 0) {
            firewall_selected_index--;
        } else if (ch == KEY_DOWN &&
                   firewall_selected_index + 1 < static_cast<int>(firewall_rows.size())) {
            firewall_selected_index++;
        } else if (ch == 'a' || ch == 'A') {
            const std::string input = prompt_input("Add IP/CIDR: ");
            auto parsed = util::ipv4::parse_cidr(input);
            if (parsed.is_ok()) {
                struct lpm_key key = {parsed.value().second, parsed.value().first};
                uint8_t val = 1;
                bpf_map_update_elem(blacklist_fd, &key, &val, BPF_ANY);
            }
        } else if ((ch == 'd' || ch == 'D') && firewall_selected_index >= 0 &&
                   firewall_selected_index < static_cast<int>(firewall_rows.size())) {
            const FirewallRow &row = firewall_rows[static_cast<size_t>(firewall_selected_index)];
            struct lpm_key key = {row.prefixlen, row.ip};
            bpf_map_delete_elem(blacklist_fd, &key);
        }
    } else if (current_view == View::Demos) {
        if (ch == 't' || ch == 'T') {
            const std::string input = prompt_input("Target IP: ");
            if (!input.empty())
                demo_cfg.target_ip = input;
        } else if (ch == 'o' || ch == 'O') {
            const std::string input = prompt_input("Target port: ");
            uint16_t port = 0;
            if (parse_u16_input(input, port))
                demo_cfg.target_port = port;
        } else if (ch == 'r' || ch == 'R') {
            const std::string input = prompt_input("Rate (pps): ");
            uint32_t rate = 0;
            if (parse_u32_input(input, rate))
                demo_cfg.rate_pps = rate;
        } else if (ch == 'd' || ch == 'D') {
            const std::string input = prompt_input("Duration (s): ");
            uint32_t duration = 0;
            if (parse_u32_input(input, duration))
                demo_cfg.duration_s = duration;
        } else if (ch == 's' || ch == 'S') {
            launch_demo("syn-flood");
            current_view = View::Threats;
        } else if (ch == 'p' || ch == 'P') {
            launch_demo("ping-flood");
            current_view = View::Dashboard;
        } else if (ch == 'u' || ch == 'U') {
            launch_demo("udp-storm");
            current_view = View::Dashboard;
        }
    }
}

void App::launch_demo(const std::string &name) {
    if (demo_thread.joinable())
        demo_thread.join();

    const demo::DemoConfig cfg = demo_cfg;
    demo_thread = std::thread([name, cfg]() {
        if (name == "syn-flood")
            demo::run_syn_flood(cfg);
        else if (name == "ping-flood")
            demo::run_ping_flood(cfg);
        else if (name == "udp-storm")
            demo::run_udp_storm(cfg);
    });
}

void App::render() {
    erase();
    int max_y = 0;
    int max_x = 0;
    getmaxyx(stdscr, max_y, max_x);

    const std::string uptime = format_duration(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start_time));

    if (color_enabled)
        attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(0, 0,
             "kwatch %s · mode=%s · pps=%lu · uptime=%s · events_dropped=%lu · rb_errs=%lu · "
             "[1]Dash [2]Threats [3]Firewall [4]Demo [q]Quit",
             iface.c_str(), mode.c_str(), current_pps, uptime.c_str(), event_drop_count,
             ringbuf_error_count);
    if (color_enabled)
        attroff(COLOR_PAIR(1) | A_BOLD);

    switch (current_view) {
    case View::Dashboard: {
        mvprintw(2, 0, "Traffic (PPS)");
        mvprintw(3, 0, "%s", widgets::render_sparkline(pps_points, max_x - 2).c_str());

        const uint64_t total = protocol_total(protocol_breakdown);
        mvprintw(5, 0, "Protocol Breakdown");
        mvprintw(6, 0, "---------------------------------");
        mvprintw(7, 0, "TCP   %10lu (%2lu%%)", protocol_breakdown.tcp,
                 protocol_pct(protocol_breakdown.tcp, total));
        mvprintw(8, 0, "UDP   %10lu (%2lu%%)", protocol_breakdown.udp,
                 protocol_pct(protocol_breakdown.udp, total));
        mvprintw(9, 0, "ICMP  %10lu (%2lu%%)", protocol_breakdown.icmp,
                 protocol_pct(protocol_breakdown.icmp, total));
        mvprintw(10, 0, "Other %10lu (%2lu%%)", protocol_breakdown.other,
                 protocol_pct(protocol_breakdown.other, total));
        mvprintw(11, 0, "Drops %10lu", protocol_breakdown.dropped);

        mvprintw(13, 0, "Recent Events");
        mvprintw(
            14, 0,
            "--------------------------------------------------------------------------------");
        std::lock_guard<std::mutex> lock(events_mutex);
        const size_t visible_events = max_y > 16 ? static_cast<size_t>(max_y - 16) : 0U;
        for (size_t i = 0; i < recent_events.size() && i < 20U && i < visible_events; ++i) {
            const auto &e = recent_events[recent_events.size() - 1U - i];
            if (e.protocol == 1U) {
                mvprintw(15 + static_cast<int>(i), 0, "%s -> %s type=%u code=%u ttl=%u",
                         util::ipv4::format(e.src_ip).c_str(), util::ipv4::format(e.dst_ip).c_str(),
                         static_cast<unsigned>(e.icmp_type), static_cast<unsigned>(e.icmp_code),
                         static_cast<unsigned>(e.ttl));
                continue;
            }
            mvprintw(15 + static_cast<int>(i), 0, "%s:%u -> %s:%u flags=%s ttl=%u",
                     util::ipv4::format(e.src_ip).c_str(), e.sport,
                     util::ipv4::format(e.dst_ip).c_str(), e.dport,
                     format_tcp_flags(e.tcp_flags).c_str(), static_cast<unsigned>(e.ttl));
        }
        break;
    }
    case View::Threats: {
        mvprintw(2, 0, "Threat Matrix (Top Connections)");
        mvprintw(
            3, 0,
            "--------------------------------------------------------------------------------");
        mvprintw(4, 0, "%-16s %-8s %-8s %-8s %-16s %-16s", "Source IP", "SYNs", "ACKs", "Ratio",
                 "Heuristic", "Status");
        int line = 5;
        for (const auto &row : threat_rows) {
            if (line >= max_y - 1)
                break;
            const std::string ratio = format_ratio(row.syn_count, row.ack_count);
            if (row.flagged && color_enabled)
                attron(COLOR_PAIR(3));
            mvprintw(line++, 0, "%-16s %-8u %-8u %-8s %-16s %-16s",
                     util::ipv4::format(row.ip).c_str(), row.syn_count, row.ack_count,
                     ratio.c_str(), get_os_from_ttl(row.ttl), row.flagged ? "SYN_FLOOD" : "OK");
            if (row.flagged && color_enabled)
                attroff(COLOR_PAIR(3));
        }
        break;
    }
    case View::Firewall: {
        mvprintw(2, 0, "Firewall (Blacklist) · [UP/DOWN] Select · [a] Add · [d] Delete");
        mvprintw(
            3, 0,
            "--------------------------------------------------------------------------------");
        mvprintw(4, 0, "  %-20s %-12s %-8s", "Prefix", "Drop Count", "Age");
        int line = 5;
        for (size_t i = 0; i < firewall_rows.size() && line < max_y - 2; ++i) {
            if (static_cast<int>(i) == firewall_selected_index)
                attron(A_REVERSE);
            mvprintw(line++, 0, "%c %-20s %-12lu %lus",
                     (static_cast<int>(i) == firewall_selected_index ? '>' : ' '),
                     (util::ipv4::format(firewall_rows[i].ip) + "/" +
                      std::to_string(firewall_rows[i].prefixlen))
                         .c_str(),
                     firewall_rows[i].drop_count, firewall_rows[i].age_s);
            if (static_cast<int>(i) == firewall_selected_index)
                attroff(A_REVERSE);
        }
        if (firewall_selected_index >= static_cast<int>(firewall_rows.size()) &&
            !firewall_rows.empty()) {
            firewall_selected_index = static_cast<int>(firewall_rows.size()) - 1;
        }
        break;
    }
    case View::Demos:
        mvprintw(2, 0, "Demo Scenarios (Loopback by default)");
        mvprintw(4, 0, "Current target: %s:%u", demo_cfg.target_ip.c_str(), demo_cfg.target_port);
        mvprintw(5, 0, "Current rate:   %u pps", demo_cfg.rate_pps);
        mvprintw(6, 0, "Current length: %u s", demo_cfg.duration_s);
        mvprintw(8, 0, "[t] Target [o] Port [r] Rate [d] Duration");
        mvprintw(9, 0, "[s] SYN Flood [p] ICMP Ping Flood [u] UDP Storm");
        mvprintw(11, 0,
                 "Targets outside loopback still require --i-know-what-im-doing via the CLI.");
        break;
    }

    refresh();
}

} // namespace tui
