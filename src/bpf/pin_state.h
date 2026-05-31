#pragma once
#include "../util/result.h"
#include <cstdint>
#include <string>

namespace bpf {

struct OwnerState {
    int pid;
    uint64_t start_time_ticks;
};

std::string pin_path_for_iface(const std::string &if_name);
std::string owner_state_dir_for_iface(const std::string &if_name);
std::string owner_pid_path_for_iface(const std::string &if_name);
util::Result<OwnerState> current_owner_state();
util::Result<OwnerState> read_owner_state(const std::string &owner_pid_path);
util::Result<int> read_owner_pid(const std::string &owner_pid_path);
bool is_owner_alive(const OwnerState &owner);
bool is_pid_alive(int pid);
util::Result<bool> cleanup_stale_state(const std::string &if_name);

} // namespace bpf
