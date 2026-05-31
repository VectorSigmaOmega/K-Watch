# K-Watch PRD - Focused Portfolio Scope

**Status:** Portfolio scope v0.2
**Owner:** Abhinash Dutta
**Last updated:** 2026-04-30
**Audience:** Kernel, Linux networking, and C++ reviewers.

## 0. Decision

K-Watch is not a production IDS, firewall platform, benchmark suite, or terminal UI product. It is a focused low-level Linux networking project meant to show competence with:

- eBPF/XDP packet parsing.
- libbpf CO-RE build flow.
- C++ RAII ownership of kernel resources.
- BPF maps as the kernel/userspace boundary.
- A small, documented CLI that can be built and tested by a reviewer.

The project is complete when the core command-line tool is correct, testable, demonstrable, and professionally documented. Safe loopback demo traffic is part of the required proof path. Optional surfaces such as TUI, auto-blocking, behavioral detection, and performance claims must not be treated as required for v1.0.

## 1. Goals

| ID | Goal |
|----|------|
| G1 | Demonstrate practical XDP/eBPF packet parsing and map use. |
| G2 | Demonstrate disciplined C++ resource management around libbpf and file descriptors. |
| G3 | Provide a single native C++ binary with no Node.js, Python service, web UI, or second runtime. |
| G4 | Be easy for a reviewer to clone, build, run on loopback or a veth pair, and inspect. |
| G5 | Keep claims honest: no unsupported production, offload, or benchmark promises. |

## 2. Non-goals for v1.0

These are deliberately out of scope for the required portfolio version:

- ncurses TUI as a required correctness surface.
- SYN-flood detection or attack classification.
- Automatic mitigation or auto-unblock TTL logic.
- 1 Mpps performance benchmark claims.
- Hardware XDP offload guarantees.
- Multi-kernel CI matrix.
- Full IPv6 parsing.
- Persistent firewall state.
- Multi-interface attach in one process.
- Production WAF, IDS, SIEM, or observability-platform behavior.

If any of these remain in the codebase, they are experimental extras. They must not appear in the required quickstart path, and failing them must not block v1.0 unless they affect the core commands below.

## 3. Required CLI

Required grammar:

```text
kwatch [GLOBAL OPTIONS] <command> [COMMAND OPTIONS] [ARGS]

Global options:
  --json                  Emit NDJSON for data output where applicable
  -v, --verbose           Increase log verbosity
  --xdp-mode <mode>       auto | skb | drv | hw  (default: auto)
  --sample-n <n>          Ring-buffer sample rate after first packet of a flow

Commands:
  run     <iface>                  Attach XDP and stream sampled packet events
  stats   <iface>                  Print protocol counter snapshot from a running instance
  block   <iface> <cidr> [<cidr>...]   Add CIDR entries to the active blacklist map
  unblock <iface> <cidr> [<cidr>...]   Remove CIDR entries from the active blacklist map
  list    <iface>                  Print active blacklist entries
  demo    <scenario>               Generate safe loopback traffic for smoke demos
  detach  <iface>                  Force-detach XDP from an interface
```

Optional commands such as `top` may exist behind an explicit non-default build flag, but they are not part of the v1.0 acceptance surface.

| ID | Requirement | Acceptance |
|----|-------------|------------|
| R1.1 | `kwatch` with no args prints help to stderr and exits 64. | `./build/kwatch >/tmp/out 2>/tmp/err; echo $?` prints `64`, and `/tmp/err` contains usage. |
| R1.2 | `kwatch --version` prints `kwatch <semver> (<git-sha>) libbpf=<version>`. | Output matches `^kwatch [0-9]+\.[0-9]+\.[0-9]+ \([0-9a-f]+|unknown\) libbpf=[0-9]+\.[0-9]+$`. |
| R1.3 | Each required command supports `--help` and includes one example. | Manual check for `run`, `stats`, `block`, `unblock`, `list`, `demo`, `detach`. |
| R1.4 | `--xdp-mode` rejects unknown values. | `kwatch --xdp-mode nope run lo` exits 64 or 65 with a clear error. |
| R1.5 | `kwatch run <iface>` emits human-readable sampled packet events. | During `ping` or `curl`, stdout includes protocol, source, destination, flags or ICMP type/code, and TTL. |
| R1.6 | `kwatch run <iface> --json` emits one JSON object per event. | `timeout 5s sudo ./build/kwatch run lo --json | head -1 | jq -e .` succeeds when traffic is present. |
| R1.7 | `stats`, `block`, `unblock`, and `list` operate on a running `kwatch run` instance. If no active pinned maps exist, they exit 65. | `./build/kwatch stats lo` with no running instance exits 65. |
| R1.8 | `block` and `unblock` accept multiple CIDRs and exit 0 only if all succeed. | `kwatch block lo 1.1.1.1/32 bad.ip` exits 65 and reports per-entry status. |
| R1.9 | `detach` is idempotent. | `sudo ./build/kwatch detach lo; sudo ./build/kwatch detach lo` exits 0 both times. |
| R1.10 | All direct `argc`/`argv` parsing lives in `src/cli/`. | `rg 'argc|argv' src | rg -v '^src/cli/'` returns nothing. |
| R1.11 | `demo` includes safe loopback traffic generators for ICMP and UDP. | `kwatch demo ping-flood --target 127.0.0.1 --duration 2s` and `kwatch demo udp-storm --target 127.0.0.1 --duration 2s` send traffic without shelling out to `ping`, `nc`, or `hping3`. |
| R1.12 | Required demos refuse non-loopback targets unless an explicit override flag is passed. | `kwatch demo udp-storm --target 8.8.8.8` exits 64 with a clear safety error. |

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success. |
| 64 | Usage error. |
| 65 | Invalid data or missing active map state. |
| 69 | Kernel feature unavailable, including missing BTF or unsupported XDP attach. |
| 77 | Permission error; message names root, `CAP_BPF`, `CAP_NET_ADMIN`, or `CAP_NET_RAW`. |
| 125 | Internal error. |

## 4. Required BPF Program

| ID | Requirement | Acceptance |
|----|-------------|------------|
| R2.1 | BPF source lives at `bpf/kwatch.bpf.c`. | File exists and is the only XDP program source. |
| R2.2 | Build generates `include/generated/vmlinux.h`, `kwatch.bpf.o`, and skeleton headers. None are tracked by git. | `git ls-files | rg 'vmlinux\.h|kwatch\.bpf\.o|kwatch\.skel\.h'` returns nothing. |
| R2.3 | `bpftool` is discovered via `pkg-config` or `PATH`; no versioned developer path is required. | CMake configure works on a clean Ubuntu 24.04 system with `bpftool` installed. |
| R2.4 | XDP parser handles Ethernet, one VLAN tag, IPv4, TCP, UDP, and ICMP. | Integration traffic increments TCP/UDP/ICMP counters and emits events. |
| R2.5 | IPv6 and ARP are count-only sentinel paths. | Packets pass; counters increment; no full IPv6 parsing is required. |
| R2.6 | Required maps: `pkt_counts` HASH, `blacklist` LPM_TRIE, `events` RINGBUF. | `bpftool map list` after attach shows the maps. |
| R2.7 | Blacklist lookup uses CIDR-capable LPM matching. | Blocking `10.0.0.0/8` drops traffic from `10.0.0.2`. |
| R2.8 | Events include timestamp, src/dst IPv4, ports where present, protocol, TCP flags, ICMP type/code, TTL, and action. | Unit event-format tests and live `run --json` output expose these fields. |
| R2.9 | Event sampling emits the first packet of a new flow and samples later packets 1-in-N. | Code review plus a high-volume smoke test shows events are fewer than packet count. |
| R2.10 | BPF program declares GPL license. | Source contains `SEC("license") = "GPL"`. |

`flow_state` may be kept as an implementation detail for event sampling or later SYN analysis, but behavioral detection is not a v1.0 requirement.

## 5. Required Demo Traffic

Demos are required because they make the project easy to verify in a portfolio review. They are not attack tooling, benchmark tooling, or behavioral-detection proof.

| ID | Requirement | Acceptance |
|----|-------------|------------|
| R3.1 | `demo ping-flood` generates ICMP echo traffic to loopback using sockets from inside the binary. | Running it while `kwatch run lo` is active produces ICMP events or counter increments. |
| R3.2 | `demo udp-storm` generates UDP traffic to loopback using sockets from inside the binary. | Running it while `kwatch run lo` is active produces UDP events or counter increments. |
| R3.3 | Required demos reject non-loopback targets by default. | Non-loopback target exits 64 unless `--i-know-what-im-doing` is present. |
| R3.4 | Demos are bounded by duration and rate options. | `--duration` and `--rate` are parsed and validated as positive values. |
| R3.5 | `demo syn-flood` may exist as an experimental extra, but it is not required for v1.0. | Failing SYN demo behavior does not block the focused portfolio release unless it breaks shared CLI/demo parsing. |

## 6. Required Userspace Implementation

| ID | Requirement | Acceptance |
|----|-------------|------------|
| R4.1 | C++20, libbpf, libelf, zlib, and ncurses only if optional TUI is built. No Node.js or web runtime. | `git ls-files package.json` returns nothing; build links native libraries only. |
| R4.2 | All owned kernel/user resources use RAII wrappers: skeleton, bpf link, ring buffer, file descriptors, timer/signalfd if used. | Code review; no manual cleanup-only `goto` path. |
| R4.3 | XDP attach uses `bpf_link` or equivalent RAII ownership so normal exit and abrupt process death release the program. | Crash-safety integration test confirms no XDP program remains after `SIGKILL`. |
| R4.4 | Attach mode order for `auto`: drv, skb, generic. Explicit mode skips fallback. | Logs state the attached mode; invalid mode fails per R1.4. |
| R4.5 | `SIGINT` and `SIGTERM` exit cleanly. | `timeout` or `kill -TERM` stops `kwatch run` and unpins maps. |
| R4.6 | BPF load and attach permission failures exit 77 and name required privilege. | Unprivileged integration test checks exit and message. |
| R4.7 | Missing BTF or unsupported XDP exits 69 with a single-line error. | Manual or CI environment test. |
| R4.8 | Logs go to stderr in `RFC3339 level component message` format. Data stays on stdout. | `run --json` stdout is parseable JSON; logs remain text on stderr. |
| R4.9 | Active map pinning is explicit and cleaned up when `run` exits. | `stats/list/block/unblock` work while `run` is active and fail 65 after it exits. |

## 7. Required Tests and Verification

The project must have one reviewer-friendly verification path:

```bash
cmake -B build
cmake --build build
./build/kwatch_tests
find src bpf tests \( -path 'tests/vendored' -o -path 'tests/vendored/*' \) -prune -o \
  \( -name '*.cpp' -o -name '*.c' -o -name '*.h' \) -print | \
  xargs clang-format --Werror --dry-run
```

Privileged integration tests must be runnable separately:

```bash
sudo tests/integration/stats_basic.sh
sudo tests/integration/blacklist.sh
sudo tests/integration/lpm_cidr.sh
sudo tests/integration/demo_traffic.sh
sudo tests/integration/crash_safety.sh
sudo tests/integration/detach_idempotent.sh
sudo tests/integration/no_active_maps.sh
sudo tests/integration/block_partial_failure.sh
sudo tests/integration/permission_errors.sh
```

| ID | Requirement | Acceptance |
|----|-------------|------------|
| R5.1 | Unit tests cover CLI parsing, IPv4/CIDR parsing, event formatting, demo safety validation, and sampling-related state. | `./build/kwatch_tests` passes. |
| R5.2 | Integration tests cover attach/detach, stats, CIDR block/unblock, required demos, no-active-map errors, and permissions. | Privileged scripts pass on Ubuntu 24.04 with BTF. |
| R5.3 | clang-format is enforced and passes locally. | The format command above exits 0. |
| R5.4 | CI builds with GCC and Clang and runs unit tests. | GitHub Actions required checks are green. |
| R5.5 | Sanitizers are preferred but not required for v1.0. | If present, failures are treated as bugs; absence does not block v1.0. |
| R5.6 | Coverage percentage, clang-tidy, fuzzing, and kernel matrix are stretch goals. | They are not required to call the portfolio scope complete. |

## 8. Required Documentation

| ID | Requirement | Acceptance |
|----|-------------|------------|
| R6.1 | README starts with what K-Watch is, what it is not, and a short build/run/demo quickstart. | First runnable command is `sudo ./build/kwatch run lo`; demo commands are presented as proof traffic. |
| R6.2 | README does not tell users to manually recover from crashes as normal workflow. | No "run ip link xdp off if it crashes" instruction. |
| R6.3 | `docs/architecture.md` shows NIC -> XDP -> BPF maps/ring buffer -> C++ CLI/demo traffic. | Diagram and component notes match this PRD. |
| R6.4 | `docs/exit-codes.md` matches the exit-code table in this PRD. | Manual review. |
| R6.5 | Design docs may exist, but must not claim unsupported behavior. | No mandatory TUI, auto-block, SYN-flood detection, or performance claim in required docs. |

## 9. Definition of Done

K-Watch v1.0 portfolio scope is done when:

1. `cmake --build build` and `./build/kwatch_tests` pass.
2. clang-format check passes.
3. Generated BPF artifacts are not tracked.
4. `kwatch run lo` or a veth integration run attaches and streams events.
5. `stats`, `block`, `unblock`, and `list` work against a running instance and fail cleanly without one.
6. `demo ping-flood` and `demo udp-storm` generate bounded loopback traffic and refuse non-loopback targets by default.
7. `detach` is idempotent.
8. Crash-safety and permission integration tests pass.
9. README and architecture docs describe only the supported core scope.

After that, stop expanding. Optional TUI, SYN-flood classification, auto-blocking, fuzzing, coverage, and performance work should be tracked as future enhancements, not completion blockers.

## 10. Future Enhancements

These are acceptable follow-up issues after v1.0:

- TUI dashboard.
- SYN-flood detection and optional auto-blocking.
- Additional demo scenarios beyond ICMP and UDP.
- Fuzz target in CI.
- clang-tidy gate.
- Coverage reporting.
- Performance benchmark documentation.
- Kernel version matrix.
