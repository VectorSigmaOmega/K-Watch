#include "pin_state.h"
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace bpf {

std::string pin_path_for_iface(const std::string &if_name) {
    return "/sys/fs/bpf/kwatch_" + if_name;
}

std::string owner_state_dir_for_iface(const std::string &if_name) {
    return "/run/kwatch/" + if_name;
}

std::string owner_pid_path_for_iface(const std::string &if_name) {
    return owner_state_dir_for_iface(if_name) + "/owner.pid";
}

struct ProcStat {
    char state;
    uint64_t start_time_ticks;
};

static util::Result<ProcStat> read_proc_stat(int pid) {
    if (pid <= 0) {
        return util::Result<ProcStat>::Err("invalid pid");
    }

    std::ifstream stat_file("/proc/" + std::to_string(pid) + "/stat");
    if (!stat_file.is_open()) {
        return util::Result<ProcStat>::Err("proc stat missing");
    }

    std::string stat_line;
    std::getline(stat_file, stat_line);
    const size_t close_paren = stat_line.rfind(") ");
    if (close_paren == std::string::npos) {
        return util::Result<ProcStat>::Err("proc stat invalid");
    }

    std::istringstream fields(stat_line.substr(close_paren + 2U));
    std::string token;
    ProcStat stat{};
    for (int field = 3; fields >> token; ++field) {
        if (field == 3) {
            stat.state = token.empty() ? '\0' : token[0];
            continue;
        }
        if (field == 22) {
            try {
                size_t pos = 0;
                const unsigned long long parsed = std::stoull(token, &pos, 10);
                if (pos != token.size()) {
                    return util::Result<ProcStat>::Err("proc start time invalid");
                }
                stat.start_time_ticks = static_cast<uint64_t>(parsed);
                return util::Result<ProcStat>::Ok(stat);
            } catch (...) {
                return util::Result<ProcStat>::Err("proc start time invalid");
            }
        }
    }

    return util::Result<ProcStat>::Err("proc start time missing");
}

util::Result<OwnerState> current_owner_state() {
    const int pid = static_cast<int>(getpid());
    auto stat = read_proc_stat(pid);
    if (!stat.is_ok()) {
        return util::Result<OwnerState>::Err(stat.error());
    }
    return util::Result<OwnerState>::Ok(OwnerState{pid, stat.value().start_time_ticks});
}

util::Result<OwnerState> read_owner_state(const std::string &owner_pid_path) {
    FILE *fp = std::fopen(owner_pid_path.c_str(), "r");
    if (fp == nullptr) {
        return util::Result<OwnerState>::Err("owner file missing");
    }

    long pid = 0;
    unsigned long long start_time = 0;
    const int scanned = std::fscanf(fp, "%ld %llu", &pid, &start_time);
    std::fclose(fp);
    if (scanned != 2 || pid <= 0L || pid > std::numeric_limits<int>::max() || start_time == 0ULL) {
        return util::Result<OwnerState>::Err("owner file invalid");
    }

    return util::Result<OwnerState>::Ok(
        OwnerState{static_cast<int>(pid), static_cast<uint64_t>(start_time)});
}

util::Result<int> read_owner_pid(const std::string &owner_pid_path) {
    auto owner = read_owner_state(owner_pid_path);
    if (!owner.is_ok()) {
        return util::Result<int>::Err(owner.error());
    }

    return util::Result<int>::Ok(owner.value().pid);
}

bool is_owner_alive(const OwnerState &owner) {
    auto stat = read_proc_stat(owner.pid);
    if (!stat.is_ok()) {
        return false;
    }
    return stat.value().state != 'Z' && stat.value().start_time_ticks == owner.start_time_ticks;
}

bool is_pid_alive(int pid) {
    auto stat = read_proc_stat(pid);
    if (stat.is_ok()) {
        return stat.value().state != 'Z';
    }
    if (pid <= 0)
        return false;
    if (kill(pid, 0) == 0)
        return true;
    return errno == EPERM;
}

static util::Result<void> remove_dir_entries(const std::string &dir_path) {
    DIR *dir = opendir(dir_path.c_str());
    if (dir == nullptr) {
        if (errno == ENOENT) {
            return util::Result<void>::Ok();
        }
        return util::Result<void>::Err("open dir failed");
    }

    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        const std::string entry_path = dir_path + "/" + entry->d_name;
        if (unlink(entry_path.c_str()) != 0 && errno != ENOENT) {
            closedir(dir);
            return util::Result<void>::Err("unlink entry failed");
        }
    }

    closedir(dir);
    return util::Result<void>::Ok();
}

util::Result<bool> cleanup_stale_state(const std::string &if_name) {
    const std::string owner_pid_path = owner_pid_path_for_iface(if_name);
    auto owner = read_owner_state(owner_pid_path);
    if (owner.is_ok() && is_owner_alive(owner.value())) {
        return util::Result<bool>::Err("active owner exists");
    }

    bool changed = false;
    if (unlink(owner_pid_path.c_str()) == 0) {
        changed = true;
    } else if (errno != ENOENT) {
        return util::Result<bool>::Err("owner file unlink failed");
    }

    const std::string owner_state_dir = owner_state_dir_for_iface(if_name);
    if (rmdir(owner_state_dir.c_str()) == 0) {
        changed = true;
    } else if (errno != ENOENT && errno != ENOTEMPTY) {
        return util::Result<bool>::Err("owner dir remove failed");
    }

    const std::string pin_path = pin_path_for_iface(if_name);
    auto remove_entries = remove_dir_entries(pin_path);
    if (!remove_entries.is_ok()) {
        return util::Result<bool>::Err(remove_entries.error());
    }

    if (rmdir(pin_path.c_str()) == 0) {
        changed = true;
    } else if (errno != ENOENT && errno != ENOTEMPTY) {
        return util::Result<bool>::Err("pin dir remove failed");
    }

    return util::Result<bool>::Ok(changed);
}

} // namespace bpf
