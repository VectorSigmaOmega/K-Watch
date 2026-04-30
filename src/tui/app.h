#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <termios.h>
#include <thread>
#include <vector>

#include "../../bpf/kwatch_shared.h"
#include "../demo/demos.h"
#include "../util/result.h"

namespace tui {

enum class View { Dashboard, Threats, Firewall, Demos };

struct ThreatRow {
    uint32_t ip = 0;
    uint32_t syn_count = 0;
    uint32_t ack_count = 0;
    uint8_t ttl = 0;
    bool flagged = false;
};

struct FirewallRow {
    uint32_t prefixlen = 0;
    uint32_t ip = 0;
    uint64_t age_s = 0;
    uint64_t drop_count = 0;
};

struct ProtocolBreakdown {
    uint64_t tcp = 0;
    uint64_t udp = 0;
    uint64_t icmp = 0;
    uint64_t other = 0;
    uint64_t dropped = 0;
};

class App {
    View current_view = View::Dashboard;
    int firewall_selected_index = 0;
    std::atomic<bool> running{true};

    std::string iface;
    std::string mode;
    std::chrono::steady_clock::time_point start_time;
    bool color_enabled = false;
    bool termios_saved = false;
    struct termios saved_termios {};

    // State references (owned by the caller, e.g. cmd_top)
    const std::vector<uint64_t> &pps_points;
    const uint64_t &current_pps;
    std::vector<kwatch_event> &recent_events;
    std::mutex &events_mutex; // R5.9: Thread safety for demos
    const std::vector<ThreatRow> &threat_rows;
    const std::vector<FirewallRow> &firewall_rows;
    const ProtocolBreakdown &protocol_breakdown;
    const uint64_t &ringbuf_error_count;
    const uint64_t &event_drop_count;

    int blacklist_fd;
    demo::DemoConfig demo_cfg;

    std::thread demo_thread;

  public:
    App(const std::string &iface_name, const std::string &attach_mode,
        const std::vector<uint64_t> &pps_points_ref, const uint64_t &current_pps_ref,
        std::vector<kwatch_event> &events, std::mutex &events_mutex_ref,
        const std::vector<ThreatRow> &threat_rows_ref,
        const std::vector<FirewallRow> &firewall_rows_ref,
        const ProtocolBreakdown &protocol_breakdown_ref, const uint64_t &ringbuf_error_count_ref,
        const uint64_t &event_drop_count_ref, int bl_fd);
    ~App();

    util::Result<void> init();
    void render();
    void handle_input();
    bool is_running() const { return running; }

    void launch_demo(const std::string &name);
};

} // namespace tui
