#include "parser.h"
#include <iostream>
#include <bpf/libbpf.h>

namespace cli {

void print_help(const std::string& bin_name, Command cmd) {
    if (cmd == Command::None) {
        std::cerr << "Usage: " << bin_name << " [GLOBAL OPTIONS] <command> [COMMAND OPTIONS] [ARGS]\n\n"
                  << "Global options:\n"
                  << "  --json                  Emit machine-readable NDJSON where applicable\n"
                  << "  -v, --verbose           Increase log verbosity (repeatable: -vv)\n"
                  << "  --xdp-mode <mode>       skb | drv | hw  (default: auto, prefer drv -> skb)\n"
                  << "  --syn-threshold <n>     SYN flood threshold (default: 100)\n"
                  << "  --syn-window <s>        SYN flood window in seconds (default: 10)\n"
                  << "  --auto-block            Automatically block IPs flagged as SYN_FLOOD (default: false)\n"
                  << "  --auto-block-ttl <s>    Auto-block cooldown in seconds (default: 300)\n\n"
                  << "Commands:\n"
                  << "  run     <iface>                  Attach XDP, stream events to stdout (default)\n"
                  << "  top     <iface>                  Attach XDP, open interactive ncurses dashboard\n"
                  << "  block   <iface> <ip> [<ip>...]   Add IPs to the blacklist map\n"
                  << "  unblock <iface> <ip> [<ip>...]   Remove IPs from the blacklist map\n"
                  << "  list    <iface>                  Print current blacklist (one IP per line)\n"
                  << "  stats   <iface>                  Snapshot of protocol counts (one-shot, exits)\n"
                  << "  demo    <scenario>               Run a built-in traffic scenario\n"
                  << "  detach  <iface>                  Force-detach any XDP program on <iface>\n";
    } else {
        std::cerr << "Subcommand help not yet implemented fully.\n";
    }
}

void print_version() {
    // R1.3: kwatch <semver> (<git-sha>) libbpf=<version>
    std::cout << "kwatch 1.0.0 (f06c1a2) libbpf=" 
              << libbpf_major_version() << "." << libbpf_minor_version() << "\n";
}

util::Result<ParsedCommand> parse_args(int argc, char** argv) {
    ParsedCommand p;
    if (argc < 2) {
        return util::Result<ParsedCommand>::Err("No command provided");
    }

    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "--json") {
            p.globals.json = true;
        } else if (arg == "-v" || arg == "--verbose") {
            p.globals.verbose++;
        } else if (arg == "-vv") {
            p.globals.verbose += 2;
        } else if (arg == "--xdp-mode") {
            if (i + 1 < argc) {
                p.globals.xdp_mode = argv[++i];
            } else {
                return util::Result<ParsedCommand>::Err("--xdp-mode requires an argument");
            }
        } else if (arg == "--syn-threshold") {
            if (i + 1 < argc) p.globals.syn_threshold = static_cast<uint32_t>(std::stoul(argv[++i]));
            else return util::Result<ParsedCommand>::Err("--syn-threshold requires an argument");
        } else if (arg == "--syn-window") {
            if (i + 1 < argc) p.globals.syn_window = static_cast<uint32_t>(std::stoul(argv[++i]));
            else return util::Result<ParsedCommand>::Err("--syn-window requires an argument");
        } else if (arg == "--auto-block") {
            p.globals.auto_block = true;
        } else if (arg == "--auto-block-ttl") {
            if (i + 1 < argc) p.globals.auto_block_ttl = static_cast<uint32_t>(std::stoul(argv[++i]));
            else return util::Result<ParsedCommand>::Err("--auto-block-ttl requires an argument");
        } else if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            exit(0);
        } else if (arg == "--version") {
            print_version();
            exit(0);
        } else if (!arg.empty() && arg[0] == '-') {
            return util::Result<ParsedCommand>::Err("Unknown global option: " + arg);
        } else {
            if (arg == "run") p.cmd = Command::Run;
            else if (arg == "top") p.cmd = Command::Top;
            else if (arg == "block") p.cmd = Command::Block;
            else if (arg == "unblock") p.cmd = Command::Unblock;
            else if (arg == "list") p.cmd = Command::List;
            else if (arg == "stats") p.cmd = Command::Stats;
            else if (arg == "demo") p.cmd = Command::Demo;
            else if (arg == "detach") p.cmd = Command::Detach;
            else {
                return util::Result<ParsedCommand>::Err("Unknown command: " + arg);
            }
            i++;
            break;
        }
        i++;
    }

    if (p.cmd == Command::None) {
        return util::Result<ParsedCommand>::Err("No command provided");
    }

    while (i < argc) {
        p.args.push_back(argv[i++]);
    }

    return util::Result<ParsedCommand>::Ok(p);
}

} // namespace cli