#include "parser.h"
#include "../log/log.h"
#include <cstdio>

using namespace cli;

int main(int argc, char** argv) {
    auto res = parse_args(argc, argv);
    if (!res.is_ok()) {
        // R1.1: no args / bad args → help to stderr, exit 64.
        if (argc >= 2) {
            std::fprintf(stderr, "kwatch: %s\n\n", res.error().c_str());
        }
        print_help(argv[0]);
        return 64; // EX_USAGE
    }

    const auto& parsed = res.value();

    // Setup logging
    kwlog::Level level = kwlog::Level::Info;
    if (parsed.globals.verbose == 1) level = kwlog::Level::Debug;
    else if (parsed.globals.verbose >= 2) level = kwlog::Level::Trace;
    kwlog::set_level(level);
    kwlog::init_libbpf_logging();

    switch (parsed.cmd) {
        case Command::Run: return cmd_run(parsed.globals, parsed.args);
        case Command::Top: return cmd_top(parsed.globals, parsed.args);
        case Command::Block: return cmd_block(parsed.globals, parsed.args);
        case Command::Unblock: return cmd_unblock(parsed.globals, parsed.args);
        case Command::List: return cmd_list(parsed.globals, parsed.args);
        case Command::Stats: return cmd_stats(parsed.globals, parsed.args);
        case Command::Demo: return cmd_demo(parsed.globals, parsed.args);
        case Command::Detach: return cmd_detach(parsed.globals, parsed.args);
        default: return 64;
    }
}