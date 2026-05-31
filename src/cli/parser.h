#pragma once
#include "../util/result.h"
#include <cstdint>
#include <string>
#include <vector>

namespace cli {

enum class Command : uint8_t {
    None,
    Run,
#ifdef KWATCH_WITH_TUI
    Top,
#endif
    Block,
    Unblock,
    List,
    Stats,
    Demo,
    Detach
};

struct GlobalOptions {
    bool json = false;
    int verbose = 0;
    std::string xdp_mode = "auto";
    uint32_t syn_threshold = 100;
    uint32_t syn_window = 10;
    bool auto_block = false;
    uint32_t auto_block_ttl = 300;
    uint32_t sample_n = 100;
};

struct ParsedCommand {
    Command cmd = Command::None;
    GlobalOptions globals;
    std::vector<std::string> args;
};

util::Result<ParsedCommand> parse_args(int argc, char **argv);
void print_help(const std::string &bin_name, Command cmd = Command::None);
void print_version();

int cmd_run(const GlobalOptions &globals, const std::vector<std::string> &args);
#ifdef KWATCH_WITH_TUI
int cmd_top(const GlobalOptions &globals, const std::vector<std::string> &args);
#endif
int cmd_block(const GlobalOptions &globals, const std::vector<std::string> &args);
int cmd_unblock(const GlobalOptions &globals, const std::vector<std::string> &args);
int cmd_list(const GlobalOptions &globals, const std::vector<std::string> &args);
int cmd_stats(const GlobalOptions &globals, const std::vector<std::string> &args);
int cmd_demo(const GlobalOptions &globals, const std::vector<std::string> &args);
int cmd_detach(const GlobalOptions &globals, const std::vector<std::string> &args);

} // namespace cli
