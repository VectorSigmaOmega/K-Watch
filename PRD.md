# K-Watch — Product Requirements Document

**Status:** Draft v1
**Owner:** Abhinash Dutta
**Last updated:** 2026-04-26
**Audience:** Implementing engineer (human or agent). Every numbered requirement carries an acceptance clause; if the clause cannot be met, the requirement is not done.

---

## 0. How to read this document

- Numbered requirements (`R1.1`, `R3.4`, …) are normative.
- Code paths under `src/...` refer to the **target** layout (§7), not the current single-file layout.
- "Must" is a hard requirement; "should" is a strong preference.
- All commands assume Linux ≥ 5.15 with BTF available (`/sys/kernel/btf/vmlinux` exists).

---

## 1. Background

K-Watch today is a ~130-line C++ XDP loader plus a ~55-line BPF program. It works: protocol counters increment, a blacklist map drops packets. But it ships with several defects that undermine the signal it's meant to send to a kernel/networking reviewer:

1. **`vmlinux.h` (158k lines, 3.3 MB) is checked into git.** This file should be generated locally with `bpftool btf dump`. Its presence inflates clone time, kills `git blame` on any related path, and tells a reviewer "I don't know what this file is."
2. **Hardcoded path to `bpftool` in the `Makefile`:** `/usr/lib/linux-tools/6.8.0-110-generic/bpftool`. Will not build on any machine that isn't the developer's. Should be discovered via `pkg-config` / `which`.
3. **`goto cleanup` in `main()`** — a C antipattern in C++ code. RAII would handle this correctly.
4. **No XDP-detach guarantee on abnormal exit.** The README itself instructs users to run `sudo ip link set dev lo xdp off` if K-Watch crashes. That's a bug presented as documentation.
5. **No CO-RE check.** Will fail with confusing errors on kernels without BTF or with relocations that don't match.
6. **Only counts. Doesn't observe.** The "Phase 5/6" expanded roadmap (ring-buffer events, SYN/ACK ratios, auto-mitigation) is the actually-interesting part and is unimplemented.
7. **No tests, no CI, no sanitizers, no `clang-tidy`, no LICENSE-driven hygiene.**
8. **A previously-considered plan to bolt InkJS on top is rejected here.** See §4 for the reasoning.

This PRD defines what K-Watch must become to credibly demonstrate **kernel and high-performance-networking depth**.

## 2. Goals

**G1. Demonstrate eBPF/XDP depth.** Beyond protocol counts: ring-buffer event streaming, packet-anatomy extraction (TTL, TCP flags, MAC), per-IP behavioral state in BPF maps, CO-RE relocations, both SKB and native XDP attach paths.

**G2. Demonstrate disciplined kernel-userspace boundary.** Heavy work in BPF (counters, hashing, sampling). Userspace wakes at a fixed cadence (2 Hz) and drains pre-aggregated state. No per-packet syscalls in the userspace loader.

**G3. Demonstrate single-binary engineering.** One C++ binary linked against `libbpf`. No second-language UI tier. No JSON-over-stdin daemons. No JavaScript runtime.

**G4. Demonstrate engineering hygiene.** CMake, CI on every push, sanitizer builds, `clang-tidy`, fuzzing on the BPF event parser, integration tests in a netns, RAII for every kernel resource (skeleton, links, maps, ring-buffer epoll fds).

**G5. Be honest about scope.** K-Watch is **not** a production WAF, IDS, or observability platform. It is a focused demonstration of the eBPF/XDP path. Say so in the README; document the deliberate scope decisions.

## 3. Non-goals

- **IPv6 parsing.** v1.0 is IPv4-only. Document this and leave a `TODO` at the parser entry point.
- **TC ingress / TC egress / cgroup-bpf hooks.** XDP only.
- **Kernel module / kprobe-based observation.** Pure XDP + maps + ring buffer.
- **A second-process daemon, IPC layer, JSON-over-stdin protocol, or web/Node UI.** Single binary, in-process state.
- **Multi-interface attach.** One interface per `kwatch run` invocation.
- **Production resilience.** No persistent storage of blocklists, no clustering, no high-availability story. Every blocklist is in-memory and dies with the process.
- **Replacement for `bpftrace`, `tcpdump`, `bpftop`.** K-Watch is a focused, opinionated demo.

## 4. Reviewer journey, audience split, and the InkJS rejection

The repo has **two audiences** that must be served separately. Conflating them is the most common failure mode for portfolio projects.

- **Audience A — non-technical (recruiters, HR).** They never run the binary. They see the README header, the language stats sidebar, the first piece of media, the "About" blurb. Reached only by **README media**.
- **Audience B — hiring engineers (kernel / networking / SRE).** They clone, build, and run. They are evaluating *kernel and systems-engineering judgment*. Reached by **the binary's CLI** and **the code's layout**.

These two audiences want opposite things from the binary's default behavior. Audience A would be charmed by an Ink-rendered React TUI; Audience B would read it as a category error and downgrade the project on the spot. eBPF tooling lives in a single-language ecosystem (`bpftop`, `bpftrace`, `pwru`, `bpfman`, `xdp-tools`, Cilium) — adding Node.js or any second runtime broadcasts "I do not know what this category looks like."

**Decision.**
1. Audience A is served by the README: an asciinema cast on top showing the binary doing real kernel work (per §5.6).
2. Audience B is served by the binary: a subcommand CLI that streams NDJSON by default (per §5.1), with an opt-in `kwatch top` subcommand for an interactive live dashboard (per §5.5).
3. The interactive view is implemented in **C++** with `ncurses` or hand-rolled ANSI rendering. **No Node.js, no Ink, no React, no second process.** This is a hard constraint, not a preference.

Audience B's 5-minute walkthrough:

1. Lands on the README. Below the title: an autoplaying asciinema cast of `kwatch run lo` streaming a SYN-flood scenario being detected.
2. Reads the one-paragraph "what and why" — including non-goals.
3. Scrolls to an architecture diagram showing the kernel-userspace boundary (XDP program → maps → ring buffer → loader → CLI/TUI).
4. Notices: green CI, coverage badge, `SECURITY.md`, `docs/design/` with 5+ short notes (including `xdp-attach-modes.md`, `co-re.md`, `behavioral-detection.md`).
5. Opens `docs/design/co-re.md` out of curiosity. Finds two paragraphs explaining why `vmlinux.h` is **not** in this repo and how it's generated.

If they reach step 5, you have their attention.

## 5. Functional requirements

### 5.1 CLI surface

The CLI must follow this grammar:

```
kwatch [GLOBAL OPTIONS] <command> [COMMAND OPTIONS] [ARGS]

Global options:
  --json                  Emit machine-readable NDJSON where applicable
  -v, --verbose           Increase log verbosity (repeatable: -vv)
  --xdp-mode <mode>       skb | drv | hw  (default: auto, prefer drv → skb)

Commands:
  run     <iface>                  Attach XDP, stream events to stdout (default)
  top     <iface>                  Attach XDP, open interactive ncurses dashboard
  block   <iface> <ip> [<ip>...]   Add IPs to the blacklist map
  unblock <iface> <ip> [<ip>...]   Remove IPs from the blacklist map
  list    <iface>                  Print current blacklist (one IP per line)
  stats   <iface>                  Snapshot of protocol counts (one-shot, exits)
  demo    <scenario>               Run a built-in traffic scenario (see §5.5.4)
  detach  <iface>                  Force-detach any XDP program on <iface>
```

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R1.1  | `kwatch` with no args prints help to stderr and exits 64 (`EX_USAGE`). It must **not** open the TUI. | `./kwatch; echo $?` prints help and emits `64`. |
| R1.2  | Every subcommand supports `--help` with at least one example. | `kwatch run --help` shows `--json` and an example. |
| R1.3  | `kwatch --version` prints `kwatch <semver> (<git-sha>) libbpf=<version>`. | Output matches the documented regex. |
| R1.4  | `kwatch run <iface>` (no `--json`) prints human-readable lines: `<RFC3339> <PROTO> <SRC>:<SPORT> -> <DST>:<DPORT> flags=<S|A|P|F|R> ttl=<n>`. | Manual: run during a `curl` and a `ping`; lines appear. |
| R1.5  | `kwatch run <iface> --json` prints one JSON object per event, each line independently parseable by `jq`. | `kwatch run lo --json \| head -10 \| jq -e .` exits 0. |
| R1.6  | `block` and `unblock` accept multiple IPs; report per-IP success/failure to stderr; exit 0 only if all succeeded. | Test: `kwatch block lo 1.1.1.1 not.an.ip; echo $?` → 65. |
| R1.7  | `detach` is idempotent and never fails on "no program attached." | `kwatch detach lo; kwatch detach lo; echo $?` → 0 both times. |
| R1.8  | Documented exit codes: 0 success, 64 usage error, 65 config/data error, 69 kernel feature unavailable (no BTF, XDP unsupported), 77 permission error (need `CAP_SYS_ADMIN`/`CAP_BPF`), 124 timeout, 125 internal error. | `docs/exit-codes.md`. |
| R1.9  | All argv parsing lives in `src/cli/`. No `argv` access elsewhere. | `grep -rE 'argv\|argc' src/ \| grep -v src/cli/` returns nothing. |

### 5.2 BPF program (kernel side)

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R2.1  | Source lives at `bpf/kwatch.bpf.c`. Compiled with `clang -target bpf -g -O2 -D__TARGET_ARCH_x86 -mcpu=v3`. | Inspect `Makefile`/`CMakeLists.txt`. |
| R2.2  | Uses CO-RE relocations: `BPF_CORE_READ`, `bpf_core_field_exists`, etc. for *every* kernel struct field access. | Run on two different kernel versions (CI matrix); both load. |
| R2.3  | Parses Ethernet, then **dispatches by ethertype** to: IPv4 (full), IPv6 (sentinel — increment a counter only, exit), VLAN (single tag, then re-dispatch), ARP (counter, exit). | Unit-feed a VLAN-tagged frame in the userspace replay test (§9); IPv4-inside-VLAN is parsed. |
| R2.4  | Parses IPv4 → TCP/UDP/ICMP. For TCP, extracts source/dest port and the flags byte (SYN, ACK, FIN, RST, PSH). For UDP, source/dest port. For ICMP, type and code. | Verifier-accepted; integration test asserts a `SYN+ACK` packet is reported with both flags set. |
| R2.5  | Maps:<br>• `pkt_counts` (HASH, key=u32 protocol, value=u64) — preserved.<br>• `blacklist` (LPM_TRIE, key={prefixlen,u32}, value=u8) — **upgrade from HASH** to support CIDR blocks.<br>• `events` (RINGBUF, 256 KiB) — new.<br>• `flow_state` (HASH, key=`{src_ip,dst_ip,sport,dport}`, value=`{syn_count,ack_count,first_seen_ns,last_seen_ns}`, max_entries=65536) — new (M4).<br>• `pps_window` (PERCPU_ARRAY, 60 slots × 8 bytes, one per second, ring) — new (M3). | Run `bpftool map list` after attach; all maps present. |
| R2.6  | Sampling policy for `events` ring buffer: **emit on first packet of a new flow** (key absent in `flow_state`), and 1-in-N for subsequent packets where N is configurable via a `volatile const __u32 sample_n` (default 100). | Manual: high-traffic test produces ≪ packet count of ringbuf events. |
| R2.7  | The XDP program must compile to **≤ 4096 BPF instructions** under `-O2` (verifier limit headroom). | `bpftool prog dump xlated` reports < 4096. |
| R2.8  | `LICENSE` declared `"GPL"` (already present; preserve). | Inspect source. |

### 5.3 Userspace loader

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R3.1  | All BPF resources owned by RAII wrappers in `src/bpf/`. Skeleton, link, ring buffer, epoll fds — every one wrapped. | `grep -n 'goto ' src/` returns nothing. |
| R3.2  | XDP attach order: try `XDP_FLAGS_DRV_MODE` → fall back to `XDP_FLAGS_SKB_MODE` → fall back to `0`. Log which mode succeeded. `--xdp-mode` overrides this and skips fallback. | Test on `lo` (which only supports SKB); log shows `mode=skb`. |
| R3.3  | An RAII guard ensures `bpf_xdp_detach` runs on **every exit path**, including `SIGTERM`, `SIGINT`, `SIGSEGV`, and uncaught exceptions. Use `signalfd(2)` integrated into the main `epoll` loop — do **not** install async signal handlers for cleanup. The current `volatile bool keep_running` pattern must be replaced. | Test: send `SIGSEGV` to a running `kwatch run`; assert `ip link show dev lo` reports no `xdp/xdpgeneric` afterwards. |
| R3.4  | The userspace loop runs at exactly 2 Hz (500 ms tick) for stats aggregation, driven by `timerfd_create`. Event ring-buffer drain is event-driven via `ring_buffer__poll` on the same epoll loop. | Code review of the main loop; `strace -c` shows ~2 wake-ups per second when idle. |
| R3.5  | At each 500 ms tick: snapshot all maps, compute deltas vs. previous snapshot, derive PPS per protocol, push into the bounded sparkline buffer (60 entries) for `kwatch top`. No allocation in the tick path beyond pre-sized buffers. | Code review; ASan run shows no allocations attributed to the tick path during a 60-second run. |
| R3.6  | CO-RE failure (no BTF, missing field) must produce a single-line error stating which field is missing and exit 69, not crash. | Test: run on a synthesized environment without BTF; observe error. |
| R3.7  | `vmlinux.h` is generated at build time, not committed. The `Makefile`/`CMakeLists.txt` runs `bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/generated/vmlinux.h`. The path to `bpftool` is discovered via `pkg-config` (`pkg-config --variable=bpftool libbpf`) or `which bpftool`, with a clear error if neither works. | `git ls-files \| grep vmlinux.h` returns nothing. Hardcoded `/usr/lib/linux-tools/...` path is gone. |
| R3.8  | Permission errors (`-EPERM` on `bpf()` syscall) produce a one-line message naming the missing capability (`CAP_BPF` + `CAP_NET_ADMIN`, or root) and exit 77. | Test: run as unprivileged user; check exit code and message. |

### 5.4 Behavioral detection (M4)

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R4.1  | Per-source-IP SYN/ACK accounting in the `flow_state` map. | `bpftool map dump` shows entries during a connection storm. |
| R4.2  | `kwatch run` flags an IP as `SYN_FLOOD` when it sends ≥ `--syn-threshold N` (default 100) SYNs without matching ACKs within `--syn-window` seconds (default 10). | Integration test: `hping3 -S -p 80 --flood 127.0.0.1` triggers flag within 5s. |
| R4.3  | `--auto-block` (default OFF) inserts flagged IPs into `blacklist` automatically. When OFF, K-Watch only reports — never modifies kernel state implicitly. | Test: same scenario with and without flag; verify map only changes when flag is on. |
| R4.4  | `flow_state` entries are evicted when the map is full using LRU semantics (use `BPF_MAP_TYPE_LRU_HASH` instead of plain `HASH`). | Inspect map type; load test fills past `max_entries` without verifier error. |
| R4.5  | A per-IP cooldown (`--auto-block-ttl`, default 300s) governs auto-unblocking. Userspace tick removes expired entries from `blacklist`. | Test: trigger auto-block, wait, assert removal. |
| R4.6  | `docs/design/behavioral-detection.md` documents the false-positive scenarios (SYN-cookies, asymmetric routing, legitimate parallel connections) and the chosen thresholds with rationale. | Review. |

### 5.5 The TUI (`kwatch top`)

This subcommand is **opt-in** and is one of multiple equally-valid surfaces — not the default entry point.

#### 5.5.1 Implementation constraints

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R5.1  | Implemented in C++. Renders with `ncurses` (preferred) or hand-rolled ANSI. **No Node.js, no React, no Ink, no second process, no JSON-over-stdin IPC.** | `ldd ./kwatch` shows no `libnode`. `package.json` does not exist. |
| R5.2  | The TUI runs in the same process as the loader, reading from in-memory buffers populated by the 500 ms tick (R3.5) and the event ring buffer. | Code review of `src/tui/`. |
| R5.3  | UI updates capped at 2 Hz (matches the tick). The render loop must not call `bpf_map_lookup_elem` directly. | Verify via instrumentation. |
| R5.4  | Restores terminal state on every exit path (`tcgetattr`/`tcsetattr` + `endwin()`), including `SIGSEGV`. | Test: kill `kwatch top` mid-render; terminal remains usable without `stty sane`. |
| R5.5  | Color is gated on `isatty(STDOUT_FILENO)` AND `getenv("NO_COLOR") == nullptr`. | Test: `kwatch top lo \| cat`; output is colorless. |

#### 5.5.2 Layout

Top header (1 line): `kwatch <iface> · mode=<drv|skb|generic> · pps=<n> · uptime=<duration> · [1]Dash [2]Threats [3]Firewall [4]Demo [q]Quit`

Main area: switchable between four views. Bottom hint line: context-sensitive key bindings.

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R5.6  | View 1 — **Dashboard.** Sparkline (60s) of total PPS; protocol breakdown table (TCP/UDP/ICMP/Other with counts and percentages); scrolling event log (last 20 sampled events). | Manual; matches mock in `docs/tui-mocks/dashboard.txt`. |
| R5.7  | View 2 — **Threat Matrix.** Table of top-N source IPs by SYN count; SYN/ACK ratio column; row turns red and labels `SYN_FLOOD` per R4.2. TTL→OS heuristic column (`64→Linux`, `128→Windows`, `255→BSD`, else `?`). | Manual + integration test inspects screen capture. |
| R5.8  | View 3 — **Firewall.** Table of blacklist entries with: IP/CIDR, age, drop count (read from `pkt_counts` per-IP if extended, otherwise total drops since add). `[a]` opens an inline input prompt to add an IP/CIDR; `[d]` on a selected row removes it. | Manual. |
| R5.9  | View 4 — **Demo Scenarios.** Menu listing built-in scenarios per §5.5.4. Selecting one launches it in a background thread and switches to the relevant view. | Manual. |
| R5.10 | Number-key view switching (`1`/`2`/`3`/`4`) and `q` to quit are global; other keys are view-local. | Manual. |
| R5.11 | A view-mock in plain text exists at `docs/tui-mocks/<view>.txt` for every view, used as the source of truth during PR review. | Files exist. |

#### 5.5.3 Performance

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R5.12 | At 1 Mpps offered load on the bound interface, `kwatch top` consumes ≤ 5% of one CPU core. (XDP runs in kernel; userspace just renders.) | Benchmark in `docs/perf.md` using `pktgen` against a netns peer. |
| R5.13 | The ring-buffer drain must never block the render loop. If drain falls behind, drop oldest events (ring buffer overflow is normal under load) and increment a visible "events_dropped" counter in the header. | Inject a flood; counter increments; UI does not stall. |

#### 5.5.4 Demo scenarios

Built-in traffic generators that demonstrate K-Watch capabilities without external tools. Each spawns a thread (or `fork`+`exec`) inside the same binary.

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R5.14 | `kwatch demo ping-flood [--target 127.0.0.1] [--duration 10s]` generates an ICMP echo flood. Implementation: raw socket (`AF_INET`, `SOCK_RAW`, `IPPROTO_ICMP`), in-process. Not via `system("ping -f ...")`. | Test asserts ICMP counter rises. |
| R5.15 | `kwatch demo syn-flood [--target 127.0.0.1:80] [--rate 10000pps] [--duration 10s]` generates half-open TCP connections. Implementation: raw socket with crafted SYN packets (PacketForge-style, see sister project), in-process. | Test asserts Threat Matrix flags the source. |
| R5.16 | `kwatch demo udp-storm [...]` generates UDP traffic to a configurable port. | Test asserts UDP counter rises. |
| R5.17 | All demo scenarios refuse to target non-loopback addresses unless `--i-know-what-im-doing` is passed. (Safety: this is a portfolio project, not a stress-test tool for arbitrary networks.) | Test: `kwatch demo syn-flood --target 8.8.8.8` exits 64 with a clear error. |

### 5.6 README and demo media (Audience-A surface)

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R6.1  | README opens (above badges) with an autoplaying asciinema cast. Embedded via SVG technique that GitHub renders inline, or `agg`-rendered animated SVG checked into `docs/media/`. | View on github.com; cast plays without click. |
| R6.2  | The cast is 25–45 seconds. Story: (a) `kwatch run lo --json \| jq` showing live events; (b) trigger `kwatch demo syn-flood` in another pane; (c) cut to `kwatch top lo` showing the Threat Matrix turning red and auto-block firing. | Cast at `docs/media/demo.cast` + `docs/media/demo.svg`. |
| R6.3  | Below the cast: one paragraph (≤ 80 words) of "what and why," ending with one sentence of what it is **not** (link to §3). | Word count check during M6 review. |
| R6.4  | Architecture diagram in `docs/architecture.md`, embedded in README. Must show: NIC → XDP program → BPF maps → ring buffer → loader → CLI/TUI. Mermaid acceptable; SVG preferred. | Diagram present and renders. |
| R6.5  | A second, shorter cast (≤ 15s) further down shows `kwatch top` cycling through the four views — preserving the TUI as a "look, also this" surprise. | Cast at `docs/media/top.cast`. |
| R6.6  | The README **must not** instruct the user to run `./kwatch` with no arguments as the first step. The first command in the quickstart is `sudo kwatch run lo`. The TUI is introduced later in the doc, not first. | Manual review during M6. |
| R6.7  | A `make demo` target regenerates both casts from a checked-in script (`docs/media/record.sh`). Stale demos that drift from the real CLI are a credibility leak. | `make demo` produces fresh casts. |

### 5.7 Logging and observability

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| R7.1  | All logs go to stderr in `<RFC3339> <LEVEL> <component> key=value ...` format. The `--json` global affects only data output (stdout); logs stay text. | `grep -rn 'std::cerr <<' src/ \| grep -v 'log::'` returns nothing. |
| R7.2  | Log levels: `error`, `warn`, `info`, `debug`. Default `info`. `-v` → `debug`, `-vv` → `trace`. `libbpf` print callback is wired into the logger at `debug` level. | Manual. |
| R7.3  | On any `bpf()` syscall failure, the log line includes `op=<name> errno=<num> errstr=<strerror>` and, where applicable, the BPF verifier log. | Trigger an intentional verifier failure; verify log content. |

## 6. Non-functional requirements

| ID    | Requirement | Acceptance |
|-------|-------------|------------|
| N1    | Build clean under `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror` with GCC 12+ and Clang 16+. The current `-Wall -Wextra -O2` is insufficient. | CI matrix passes. |
| N2    | CMake project. Targets: `kwatch` (binary), `kwatch_tests` (unit), `kwatch_fuzz_parser` (libFuzzer over the userspace parser of ringbuf events), `bpf-obj` (custom command for the BPF object). | `cmake --build build --target kwatch_tests` works. |
| N3    | CI (GitHub Actions) runs on every push/PR: build (gcc-12, clang-16), unit tests, integration tests in a netns with a `veth` pair, ASan, UBSan, `clang-tidy`, fuzz smoke (60s). Kernel matrix: at least two recent LTS kernels via Vagrant or GitHub-hosted runners. | All required checks green on a no-op PR. |
| N4    | Code coverage ≥ 60% on `src/` excluding `src/cli/main.cpp` and `src/tui/render.cpp`. Reported via `gcovr`. | Coverage report uploaded. |
| N5    | `clang-tidy` config checked in (`.clang-tidy`). CI fails on new warnings. | CI step. |
| N6    | `clang-format` config checked in (`.clang-format`, LLVM-derived). CI fails on un-formatted code. | CI step. |
| N7    | Runtime dependencies: `libbpf`, `libelf`, `libz`, `libncurses`. All discoverable via `pkg-config`. No hardcoded paths. | `ldd ./kwatch` reviewed; CMake uses `find_package(PkgConfig)` only. |
| N8    | A reproducible build script (`scripts/build-in-container.sh`) that builds inside an Ubuntu 24.04 container, isolating from the host's kernel headers/`bpftool` version. | Run on a non-Ubuntu host; produces a working `kwatch`. |

## 7. Target repository layout

```
.
├── CMakeLists.txt
├── LICENSE                         (MIT or Apache-2.0; pick one and add)
├── README.md                        (rewrite per §5.6)
├── PRD.md                           (this file)
├── CONTRIBUTING.md                  (NEW)
├── SECURITY.md                      (NEW)
├── CODEOWNERS                       (NEW)
├── .clang-format                    (NEW)
├── .clang-tidy                      (NEW)
├── .editorconfig                    (NEW)
├── .gitignore                       (expand)
├── .github/workflows/ci.yml         (NEW)
├── docs/
│   ├── architecture.md
│   ├── exit-codes.md
│   ├── perf.md
│   ├── design/
│   │   ├── co-re.md                 (why vmlinux.h is generated, not committed)
│   │   ├── xdp-attach-modes.md      (drv vs skb vs hw, fallback rationale)
│   │   ├── ring-buffer-sampling.md  (R2.6 sampling policy)
│   │   ├── behavioral-detection.md  (R4.6: thresholds, false positives)
│   │   ├── lpm-blacklist.md         (why LPM_TRIE for CIDR)
│   │   └── kernel-userspace-boundary.md
│   ├── media/
│   │   ├── demo.cast
│   │   ├── demo.svg
│   │   ├── top.cast
│   │   └── record.sh
│   └── tui-mocks/
│       ├── dashboard.txt
│       ├── threats.txt
│       ├── firewall.txt
│       └── demo.txt
├── bpf/
│   └── kwatch.bpf.c                 (moved out of src/)
├── include/
│   └── generated/                   (gitignored; vmlinux.h, kwatch.skel.h)
├── src/
│   ├── cli/
│   │   ├── main.cpp
│   │   ├── parser.{h,cpp}
│   │   └── commands/
│   │       ├── run.cpp
│   │       ├── top.cpp
│   │       ├── block.cpp
│   │       ├── unblock.cpp
│   │       ├── list.cpp
│   │       ├── stats.cpp
│   │       ├── demo.cpp
│   │       └── detach.cpp
│   ├── bpf/
│   │   ├── skeleton.{h,cpp}         (RAII over the generated skeleton)
│   │   ├── attach.{h,cpp}           (XDP attach with mode fallback)
│   │   ├── maps.{h,cpp}             (typed map wrappers)
│   │   └── ringbuf.{h,cpp}          (epoll-integrated ring buffer drain)
│   ├── core/
│   │   ├── tick.{h,cpp}             (timerfd 2 Hz aggregation loop)
│   │   ├── flow_tracker.{h,cpp}     (userspace mirror of behavioral state)
│   │   ├── pps_window.{h,cpp}       (60-slot ring for sparkline)
│   │   └── blacklist.{h,cpp}        (LPM-aware add/remove/list)
│   ├── tui/
│   │   ├── app.{h,cpp}              (top-level ncurses loop)
│   │   ├── views/
│   │   │   ├── dashboard.cpp
│   │   │   ├── threats.cpp
│   │   │   ├── firewall.cpp
│   │   │   └── demos.cpp
│   │   └── widgets/
│   │       ├── sparkline.{h,cpp}
│   │       └── table.{h,cpp}
│   ├── demo/
│   │   ├── ping_flood.{h,cpp}
│   │   ├── syn_flood.{h,cpp}
│   │   └── udp_storm.{h,cpp}
│   ├── log/
│   │   └── log.{h,cpp}
│   └── util/
│       ├── result.h                 (Result<T,E> or std::expected)
│       ├── ipv4.{h,cpp}             (parse/format, CIDR)
│       └── signals.{h,cpp}          (signalfd integration)
├── tests/
│   ├── unit/
│   │   ├── ipv4_test.cpp
│   │   ├── pps_window_test.cpp
│   │   ├── flow_tracker_test.cpp
│   │   ├── cli_parser_test.cpp
│   │   └── ringbuf_event_parser_test.cpp
│   ├── integration/
│   │   ├── attach_detach.sh
│   │   ├── stats_basic.sh
│   │   ├── blacklist.sh
│   │   ├── lpm_cidr.sh
│   │   ├── syn_flood_detection.sh
│   │   ├── auto_block.sh
│   │   ├── crash_safety.sh          (SIGSEGV → XDP detached)
│   │   └── permission_errors.sh
│   └── fuzz/
│       └── ringbuf_event_parser_fuzz.cpp
├── scripts/
│   ├── build-in-container.sh
│   ├── netns-veth-setup.sh          (used by integration tests)
│   └── gen-vmlinux.sh
└── examples/
    └── (no committed binaries; examples are scripts only)
```

`kwatch`, `kwatch_output.log`, `src/vmlinux.h`, `src/kwatch.skel.h`, `src/kwatch.bpf.o` — **all currently checked in** — must be removed from git history in M1. Add to `.gitignore`.

## 8. Threat model (summary)

Full threat model lives in `docs/threat-model.md`.

- **In scope:** an unprivileged user on the host attempting to abuse the K-Watch interface (e.g., flooding the blacklist, exhausting flow_state); a hostile network attempting to evade detection or trigger false positives that cause auto-block of legitimate traffic.
- **Out of scope:** a malicious eBPF program loaded by another root user; kernel 0-days; the developer's host being compromised.
- **Defenses:**
  - Auto-block defaults to OFF.
  - Auto-block has a TTL and is bounded by the blacklist map's `max_entries`.
  - `flow_state` is `LRU_HASH` so resource exhaustion can't lock out new flows.
  - Demo scenarios refuse non-loopback targets without explicit override.

## 9. Testing strategy

- **Unit tests** (doctest, vendored): IPv4/CIDR parser, PPS sliding window, flow tracker eviction, ringbuf event parser, CLI parser.
- **Integration tests** (bash, run in CI inside a privileged container with a `veth` pair):
  - `attach_detach.sh`: attach, kill -SEGV, verify XDP detached on the interface.
  - `blacklist.sh`: block, generate traffic, assert drops via `pkt_counts`.
  - `lpm_cidr.sh`: block `10.0.0.0/8`, verify matches.
  - `syn_flood_detection.sh`: generate SYNs via `kwatch demo syn-flood`, assert detection within 5s.
  - `auto_block.sh`: same, with `--auto-block`, assert IP appears in `blacklist`.
  - `permission_errors.sh`: run as non-root, assert exit 77 and the message names `CAP_BPF`.
- **Fuzzing:** libFuzzer over the userspace ringbuf event parser. CI runs 60s; nightly runs 10 minutes.
- **Sanitizers:** ASan + UBSan builds in CI.
- **Static analysis:** `clang-tidy` with `bugprone-*`, `cert-*`, `clang-analyzer-*`, `performance-*`, `readability-*`.

## 10. Milestones

Each milestone ends in a tagged release.

### M1 — Foundation and safety  →  `v0.1`

**Scope.** Boring-but-necessary, plus fix the four defects that would tank a code review.

- [ ] `Makefile` → `CMakeLists.txt` per §7. `bpftool` discovered via `pkg-config` / `which`, **not** hardcoded.
- [ ] `vmlinux.h` removed from git (`git filter-repo`); generated at build time (R3.7).
- [ ] `kwatch` binary, `kwatch.skel.h`, `kwatch.bpf.o`, `kwatch_output.log` removed from git; expand `.gitignore`.
- [ ] Replace `goto cleanup` with RAII (R3.1).
- [ ] RAII XDP-detach guarantee on every exit path including `SIGSEGV` (R3.3).
- [ ] Fix the README so it does **not** instruct manual `ip link set dev lo xdp off` recovery — that should be impossible after R3.3.
- [ ] CI skeleton: build (gcc, clang), `clang-format` check, `clang-tidy`.
- [ ] LICENSE, CONTRIBUTING.md, SECURITY.md, CODEOWNERS.

**Exit criteria.** Repo size on disk < 200 KB checked-in source. CI green. `kwatch run lo` then `kill -SEGV` leaves no XDP program attached.

### M2 — CLI redesign and refactor  →  `v0.2`

- [ ] Restructure code per §7 layout.
- [ ] Subcommand CLI per §5.1 (R1.1–R1.9).
- [ ] Structured logger in `src/log/` (R7.1–R7.3).
- [ ] CO-RE check + permission-error path (R3.6, R3.8).
- [ ] XDP attach with mode fallback (R3.2).
- [ ] timerfd-based 2 Hz tick (R3.4).
- [ ] Unit tests for CLI parser, IPv4/CIDR parser, PPS window. Coverage ≥ 50% by end of M2.

**Exit criteria.** All current behavior preserved. `kwatch run lo` works. `kwatch --help` lists all subcommands. `clang-tidy` clean.

### M3 — Ring buffer events  →  `v0.3`

- [ ] Ring buffer map and event struct (R2.5, R2.6).
- [ ] BPF program parses TCP flags, ports, TTL, MAC (R2.4).
- [ ] LPM_TRIE blacklist for CIDR support (R2.5).
- [ ] `kwatch run` streams human and `--json` output (R1.4, R1.5).
- [ ] Integration tests `attach_detach.sh`, `stats_basic.sh`, `blacklist.sh`, `lpm_cidr.sh`.

**Exit criteria.** `kwatch run lo --json | jq -e '.tcp_flags'` works during a live `curl`.

### M4 — Behavioral detection  →  `v0.4`

- [ ] `flow_state` LRU map (R2.5, R4.4).
- [ ] SYN/ACK ratio detection in BPF + userspace flag (R4.1, R4.2).
- [ ] `--auto-block` and `--auto-block-ttl` (R4.3, R4.5).
- [ ] `docs/design/behavioral-detection.md` (R4.6).
- [ ] Integration tests `syn_flood_detection.sh`, `auto_block.sh`.

**Exit criteria.** A scripted SYN flood is detected within 5s and (with `--auto-block`) the source appears in the blacklist within 1s of detection.

### M5 — TUI (`kwatch top`)  →  `v0.5`

- [ ] `src/tui/` ncurses implementation per §5.5 (R5.1–R5.13).
- [ ] All four views per §5.5.2 with view-mocks committed.
- [ ] Demo scenarios per §5.5.4 (R5.14–R5.17).
- [ ] Performance benchmark + `docs/perf.md` (R5.12).

**Exit criteria.** `kwatch top lo` renders, switches between all four views with number keys, and `kwatch top` followed by `kwatch demo syn-flood` lights up the Threat Matrix. Killing it with `SIGKILL` leaves the terminal usable.

### M6 — Polish, docs, demo  →  `v1.0`

- [ ] Primary asciinema cast (R6.1, R6.2).
- [ ] Secondary `kwatch top` cast (R6.5).
- [ ] `make demo` regeneration target (R6.7).
- [ ] Architecture diagram (R6.4).
- [ ] README rewrite per R6.3, R6.6.
- [ ] All `docs/design/` notes complete.
- [ ] Fuzz target in nightly CI for 10 minutes.
- [ ] Coverage badge ≥ 60%.

**Exit criteria.** Two success conditions, one per audience:
- **Audience A:** opening the README on github.com shows an animated demo of the SYN-flood detection within 3 seconds of page load, no clicks.
- **Audience B:** a cold reviewer can `git clone && cmake -B build && cmake --build build && sudo ./build/kwatch run lo --json` in under 5 minutes following the README.

## 11. Open questions

- **`vmlinux.h` for non-Ubuntu kernels.** Some distros don't expose `/sys/kernel/btf/vmlinux`. Fall back to a vendored `vmlinux-min.h` containing only the structs we use? Decide at M2.
- **Test runner for kernel matrix.** GitHub-hosted runners ship one kernel; matrixing requires Vagrant or a third-party action. Defer to M2; M1 CI can be single-kernel.
- **TUI library.** `ncurses` is ubiquitous but old; `notcurses` is modern but a less common dependency. Default to `ncurses`; revisit if it becomes painful.
- **Auto-block rate-limiting.** Should there be a global cap on auto-block insertions per second to prevent map exhaustion under sustained attack? Likely yes; specify in M4 PR review.

## 12. Out of scope (explicit, on the record)

- IPv6 packet parsing (sentinel counter only)
- TC ingress/egress hooks
- cgroup-bpf, kprobes, uprobes
- A second-process daemon, JSON-over-stdin protocol, Node.js / React / Ink TUI
- Web dashboard or HTTP API
- Persistent blocklist storage / database
- Multi-interface attach in one process
- Production-grade resilience (HA, failover, replication)
- Replacement for `bpftrace`, `tcpdump`, `bpftop`, Cilium, or any other established tool
