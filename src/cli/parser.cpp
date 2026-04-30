#include "parser.h"
#include <bpf/libbpf.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace cli {

static void usage(const std::string &s) { (void)std::fputs(s.c_str(), stderr); }

void print_help(const std::string &bin_name, Command cmd) {
    if (cmd == Command::None) {
        std::string s =
            "Usage: " + bin_name +
            " [GLOBAL OPTIONS] <command> [COMMAND OPTIONS] [ARGS]\n\n"
            "Global options:\n"
            "  --json                  Emit machine-readable NDJSON where applicable\n"
            "  -v, --verbose           Increase log verbosity (repeatable: -vv)\n"
            "  --xdp-mode <mode>       skb | drv | hw  (default: auto, prefer drv -> skb)\n"
            "  --syn-threshold <n>     SYN flood threshold (default: 100)\n"
            "  --syn-window <s>        SYN flood window in seconds (default: 10)\n"
            "  --auto-block            Automatically block IPs flagged as SYN_FLOOD (default: "
            "off)\n"
            "  --auto-block-ttl <s>    Auto-block cooldown in seconds (default: 300)\n"
            "  --sample-n <n>          Ring-buffer sample rate for existing flows (default: "
            "100)\n\n"
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
            "  sudo " +
            bin_name +
            " run lo\n"
            "  sudo " +
            bin_name + " block lo 10.0.0.0/8\n";
        usage(s);
        return;
    }
    switch (cmd) {
    case Command::Run:
        usage("Usage: " + bin_name +
              " run <iface> [--json]\n"
              "  Attach XDP and stream events.\n"
              "  Example: sudo " +
              bin_name + " run lo --json | jq\n");
        break;
    case Command::Top:
        usage("Usage: " + bin_name +
              " top <iface>\n"
              "  Launch interactive ncurses dashboard.\n"
              "  Example: sudo " +
              bin_name + " top lo\n");
        break;
    case Command::Block:
        usage("Usage: " + bin_name +
              " block <iface> <ip/cidr>...\n"
              "  Add IPs or CIDR ranges to the blacklist.\n"
              "  Example: sudo " +
              bin_name + " block lo 10.0.0.0/8\n");
        break;
    case Command::Unblock:
        usage("Usage: " + bin_name +
              " unblock <iface> <ip/cidr>...\n"
              "  Remove entries from the blacklist.\n"
              "  Example: sudo " +
              bin_name + " unblock lo 10.0.0.0/8\n");
        break;
    case Command::List:
        usage("Usage: " + bin_name +
              " list <iface>\n"
              "  Print current blacklist contents.\n"
              "  Example: sudo " +
              bin_name + " list lo\n");
        break;
    case Command::Stats:
        usage("Usage: " + bin_name +
              " stats <iface>\n"
              "  One-shot protocol-counter snapshot.\n"
              "  Example: sudo " +
              bin_name + " stats lo\n");
        break;
    case Command::Demo:
        usage("Usage: " + bin_name +
              " demo <scenario> [--target <ip[:port]>] [--rate <pps>] [--duration <s>]\n"
              "  Scenarios: syn-flood, ping-flood, udp-storm\n"
              "  Example: sudo " +
              bin_name + " demo syn-flood --target 127.0.0.1:80\n");
        break;
    case Command::Detach:
        usage("Usage: " + bin_name +
              " detach <iface>\n"
              "  Force-detach any XDP program. Idempotent.\n"
              "  Example: sudo " +
              bin_name + " detach lo\n");
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
    (void)std::fprintf(stdout, "kwatch %s (%s) libbpf=%u.%u\n", PROJECT_VERSION, GIT_SHA,
                       libbpf_major_version(), libbpf_minor_version());
}

static Command parse_subcommand(const std::string &s) {
    if (s == "run")
        return Command::Run;
    if (s == "top")
        return Command::Top;
    if (s == "block")
        return Command::Block;
    if (s == "unblock")
        return Command::Unblock;
    if (s == "list")
        return Command::List;
    if (s == "stats")
        return Command::Stats;
    if (s == "demo")
        return Command::Demo;
    if (s == "detach")
        return Command::Detach;
    return Command::None;
}

static util::Result<uint32_t> parse_u32_arg(const std::string &option, const std::string &value) {
    try {
        size_t pos = 0;
        const unsigned long parsed = std::stoul(value, &pos, 10);
        if (pos != value.size() || parsed > std::numeric_limits<uint32_t>::max()) {
            return util::Result<uint32_t>::Err("Invalid value for " + option + ": " + value);
        }
        return util::Result<uint32_t>::Ok(static_cast<uint32_t>(parsed));
    } catch (...) {
        return util::Result<uint32_t>::Err("Invalid value for " + option + ": " + value);
    }
}

static util::Result<bool> try_parse_global_option(int argc, char **argv, int &i,
                                                  ParsedCommand &parsed) {
    const std::string arg = argv[i];
    if (arg == "--json") {
        parsed.globals.json = true;
        return util::Result<bool>::Ok(true);
    }
    if (arg == "-v" || arg == "--verbose") {
        parsed.globals.verbose++;
        return util::Result<bool>::Ok(true);
    }
    if (arg == "-vv") {
        parsed.globals.verbose += 2;
        return util::Result<bool>::Ok(true);
    }
    if (arg == "--xdp-mode") {
        if (i + 1 >= argc) {
            return util::Result<bool>::Err("--xdp-mode requires an argument");
        }
        parsed.globals.xdp_mode = argv[++i];
        return util::Result<bool>::Ok(true);
    }
    if (arg == "--syn-threshold") {
        if (i + 1 >= argc) {
            return util::Result<bool>::Err("--syn-threshold requires an argument");
        }
        auto parsed_value = parse_u32_arg(arg, argv[++i]);
        if (!parsed_value.is_ok()) {
            return util::Result<bool>::Err(parsed_value.error());
        }
        parsed.globals.syn_threshold = parsed_value.value();
        return util::Result<bool>::Ok(true);
    }
    if (arg == "--syn-window") {
        if (i + 1 >= argc) {
            return util::Result<bool>::Err("--syn-window requires an argument");
        }
        auto parsed_value = parse_u32_arg(arg, argv[++i]);
        if (!parsed_value.is_ok()) {
            return util::Result<bool>::Err(parsed_value.error());
        }
        parsed.globals.syn_window = parsed_value.value();
        return util::Result<bool>::Ok(true);
    }
    if (arg == "--auto-block") {
        parsed.globals.auto_block = true;
        return util::Result<bool>::Ok(true);
    }
    if (arg == "--auto-block-ttl") {
        if (i + 1 >= argc) {
            return util::Result<bool>::Err("--auto-block-ttl requires an argument");
        }
        auto parsed_value = parse_u32_arg(arg, argv[++i]);
        if (!parsed_value.is_ok()) {
            return util::Result<bool>::Err(parsed_value.error());
        }
        parsed.globals.auto_block_ttl = parsed_value.value();
        return util::Result<bool>::Ok(true);
    }
    if (arg == "--sample-n") {
        if (i + 1 >= argc) {
            return util::Result<bool>::Err("--sample-n requires an argument");
        }
        auto parsed_value = parse_u32_arg(arg, argv[++i]);
        if (!parsed_value.is_ok()) {
            return util::Result<bool>::Err(parsed_value.error());
        }
        if (parsed_value.value() == 0U) {
            return util::Result<bool>::Err("--sample-n must be greater than zero");
        }
        parsed.globals.sample_n = parsed_value.value();
        return util::Result<bool>::Ok(true);
    }
    if (arg == "--help" || arg == "-h") {
        if (parsed.cmd == Command::None) {
            Command sub = Command::None;
            if (i + 1 < argc) {
                sub = parse_subcommand(argv[i + 1]);
            }
            print_help(argv[0], sub);
        } else {
            print_help(argv[0], parsed.cmd);
        }
        std::exit(0);
    }
    if (arg == "--version") {
        print_version();
        std::exit(0);
    }
    return util::Result<bool>::Ok(false);
}

util::Result<ParsedCommand> parse_args(int argc, char **argv) {
    ParsedCommand parsed;
    if (argc < 2) {
        return util::Result<ParsedCommand>::Err("No command provided");
    }

    for (int i = 1; i < argc; ++i) {
        auto option_result = try_parse_global_option(argc, argv, i, parsed);
        if (!option_result.is_ok()) {
            return util::Result<ParsedCommand>::Err(option_result.error());
        }
        if (option_result.value()) {
            continue;
        }

        const std::string arg = argv[i];
        if (parsed.cmd == Command::None) {
            if (!arg.empty() && arg[0] == '-') {
                return util::Result<ParsedCommand>::Err("Unknown global option: " + arg);
            }

            parsed.cmd = parse_subcommand(arg);
            if (parsed.cmd == Command::None) {
                return util::Result<ParsedCommand>::Err("Unknown command: " + arg);
            }
            continue;
        }

        parsed.args.push_back(arg);
    }

    if (parsed.cmd == Command::None) {
        return util::Result<ParsedCommand>::Err("No command provided");
    }

    return util::Result<ParsedCommand>::Ok(parsed);
}

} // namespace cli
