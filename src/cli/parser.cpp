#include "parser.h"
#include <cstdio>
#include <cstdlib>
#include <bpf/libbpf.h>

namespace cli {

static void usage(const std::string& s) { std::fputs(s.c_str(), stderr); }

void print_help(const std::string& bin_name, Command cmd) {
    if (cmd == Command::None) {
        std::string s =
            "Usage: " + bin_name + " [GLOBAL OPTIONS] <command> [COMMAND OPTIONS] [ARGS]\n\n"
            "Global options:\n"
            "  --json                  Emit machine-readable NDJSON where applicable\n"
            "  -v, --verbose           Increase log verbosity (repeatable: -vv)\n"
            "  --xdp-mode <mode>       skb | drv | hw  (default: auto, prefer drv -> skb)\n"
            "  --syn-threshold <n>     SYN flood threshold (default: 100)\n"
            "  --syn-window <s>        SYN flood window in seconds (default: 10)\n"
            "  --auto-block            Automatically block IPs flagged as SYN_FLOOD (default: off)\n"
            "  --auto-block-ttl <s>    Auto-block cooldown in seconds (default: 300)\n\n"
            "Commands:\n"
            "  run     <iface>                  Attach XDP, stream events to stdout (default)\n"
            "  top     <iface>                  Attach XDP, open interactive ncurses dashboard\n"
            "  block   <iface> <ip> [<ip>...]   Add IPs to the blacklist map\n"
            "  unblock <iface> <ip> [<ip>...]   Remove IPs from the blacklist map\n"
            "  list    <iface>                  Print current blacklist (one IP per line)\n"
            "  stats   <iface>                  Snapshot of protocol counts (one-shot, exits)\n"
            "  demo    <scenario>               Run a built-in traffic scenario\n"
            "  detach  <iface>                  Force-detach any XDP program on <iface>\n\n"
            "Examples:\n"
            "  sudo " + bin_name + " run lo\n"
            "  sudo " + bin_name + " block lo 10.0.0.0/8\n";
        usage(s);
        return;
    }
    switch (cmd) {
        case Command::Run:
            usage("Usage: " + bin_name + " run <iface> [--json]\n"
                  "  Attach XDP and stream events.\n"
                  "  Example: sudo " + bin_name + " run lo --json | jq\n");
            break;
        case Command::Top:
            usage("Usage: " + bin_name + " top <iface>\n"
                  "  Launch interactive ncurses dashboard.\n"
                  "  Example: sudo " + bin_name + " top lo\n");
            break;
        case Command::Block:
            usage("Usage: " + bin_name + " block <iface> <ip/cidr>...\n"
                  "  Add IPs or CIDR ranges to the blacklist.\n"
                  "  Example: sudo " + bin_name + " block lo 10.0.0.0/8\n");
            break;
        case Command::Unblock:
            usage("Usage: " + bin_name + " unblock <iface> <ip/cidr>...\n"
                  "  Remove entries from the blacklist.\n"
                  "  Example: sudo " + bin_name + " unblock lo 10.0.0.0/8\n");
            break;
        case Command::List:
            usage("Usage: " + bin_name + " list <iface>\n"
                  "  Print current blacklist contents.\n");
            break;
        case Command::Stats:
            usage("Usage: " + bin_name + " stats <iface>\n"
                  "  One-shot protocol-counter snapshot.\n");
            break;
        case Command::Demo:
            usage("Usage: " + bin_name + " demo <scenario> [--target <ip>] [--rate <pps>]\n"
                  "  Scenarios: syn-flood, ping-flood, udp-storm\n"
                  "  Example: sudo " + bin_name + " demo syn-flood --target 127.0.0.1\n");
            break;
        case Command::Detach:
            usage("Usage: " + bin_name + " detach <iface>\n"
                  "  Force-detach any XDP program. Idempotent.\n");
            break;
        default:
            usage("Use " + bin_name + " --help to see available commands.\n");
            break;
    }
}

void print_version() {
#ifndef PROJECT_VERSION
#define PROJECT_VERSION "0.0.0"
#endif
#ifndef GIT_SHA
#define GIT_SHA "unknown"
#endif
    std::fprintf(stdout, "kwatch %s (%s) libbpf=%u.%u\n",
                 PROJECT_VERSION, GIT_SHA,
                 libbpf_major_version(), libbpf_minor_version());
}

static Command parse_subcommand(const std::string& s) {
    if (s == "run") return Command::Run;
    if (s == "top") return Command::Top;
    if (s == "block") return Command::Block;
    if (s == "unblock") return Command::Unblock;
    if (s == "list") return Command::List;
    if (s == "stats") return Command::Stats;
    if (s == "demo") return Command::Demo;
    if (s == "detach") return Command::Detach;
    return Command::None;
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
            if (i + 1 < argc) p.globals.xdp_mode = argv[++i];
            else return util::Result<ParsedCommand>::Err("--xdp-mode requires an argument");
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
            Command sub = Command::None;
            if (i + 1 < argc) sub = parse_subcommand(argv[i+1]);
            print_help(argv[0], sub);
            std::exit(0);
        } else if (arg == "--version") {
            print_version();
            std::exit(0);
        } else if (!arg.empty() && arg[0] == '-') {
            return util::Result<ParsedCommand>::Err("Unknown global option: " + arg);
        } else {
            Command c = parse_subcommand(arg);
            if (c == Command::None) {
                return util::Result<ParsedCommand>::Err("Unknown command: " + arg);
            }
            p.cmd = c;
            i++;
            break;
        }
        i++;
    }

    if (p.cmd == Command::None) {
        return util::Result<ParsedCommand>::Err("No command provided");
    }

    while (i < argc) {
        // Subcommand-level --help
        std::string a = argv[i];
        if (a == "--help" || a == "-h") {
            print_help(argv[0], p.cmd);
            std::exit(0);
        }
        p.args.push_back(a);
        i++;
    }

    return util::Result<ParsedCommand>::Ok(p);
}

} // namespace cli
