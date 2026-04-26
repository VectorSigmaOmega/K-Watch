#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include "../util/result.h"
#include "../core/flow_tracker.h"
#include "../core/pps_window.h"
#include "../../bpf/kwatch_shared.h"

namespace tui {

enum class View { Dashboard, Threats, Firewall, Demos };

class App {
    View current_view = View::Dashboard;
    std::atomic<bool> running{true};
    
    std::string iface;
    std::string mode;
    
    // State references (owned by the caller, e.g. cmd_top)
    const core::PpsWindow& pps_window;
    std::vector<kwatch_event>& recent_events;
    std::mutex& events_mutex; // R5.9: Thread safety for demos
    const core::FlowTracker& flow_tracker;
    
    int pkt_counts_fd;
    int blacklist_fd;

    std::thread demo_thread;

public:
    App(const std::string& iface, const std::string& mode, 
        const core::PpsWindow& pps_win, std::vector<kwatch_event>& events,
        std::mutex& mtx, const core::FlowTracker& tracker,
        int pkt_fd, int bl_fd);
    ~App();

    util::Result<void> init();
    void render();
    void handle_input();
    bool is_running() const { return running; }
    
    void launch_demo(const std::string& name);
};

} // namespace tui