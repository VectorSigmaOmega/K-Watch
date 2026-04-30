# K-Watch Review Findings

Date: 2026-04-26
Scope: Review against `PRD.md` and the current checked-in code. Other docs were treated as non-authoritative.

## Confirmed Findings

1. High: Invalid numeric CLI values crash the process instead of returning `EX_USAGE` (`64`).
   Evidence: `std::stoul` / `std::stoi` are used without error handling in [src/cli/parser.cpp](src/cli/parser.cpp) and [src/cli/commands/demo.cpp](src/cli/commands/demo.cpp). `./build/kwatch --syn-threshold nope run lo` aborts with exit `134`.

2. High: The parser does not support the documented `kwatch run <iface> --json` form.
   Evidence: After the subcommand is found, remaining tokens are pushed into `args` verbatim and not parsed as globals; `cmd_run()` only consumes `args[0]`. Refs: [src/cli/parser.cpp](src/cli/parser.cpp), [src/cli/commands/run.cpp](src/cli/commands/run.cpp).

3. High: VLAN-tagged IPv4 packets can produce corrupted event metadata in the ring buffer.
   Evidence: `xdp_kwatch_prog()` advances past a VLAN header, but `emit_event()` reparses from `eth + 1` and does not reapply VLAN handling. Ref: [bpf/kwatch.bpf.c](bpf/kwatch.bpf.c).

4. Medium: Demo safety validation returns the wrong exit code.
   Evidence: Non-loopback targets are rejected in [src/demo/demos.h](src/demo/demos.h), but [src/cli/commands/demo.cpp](src/cli/commands/demo.cpp) maps all demo failures to exit `125`, while the PRD requires `64` for this case.

5. Medium: `kwatch top` still performs live BPF map syscalls and fresh allocations in its render/update path.
   Evidence: [src/cli/commands/top.cpp](src/cli/commands/top.cpp) rescans `pkt_counts` every tick, [src/tui/app.cpp](src/tui/app.cpp) walks `blacklist_fd` while rendering, and [src/core/pps_window.cpp](src/core/pps_window.cpp) allocates a fresh snapshot vector per frame.

6. Medium: The fuzz target is inert and does not exercise a real event parser/formatter path.
   Evidence: [tests/fuzz/ringbuf_event_parser_fuzz.cpp](tests/fuzz/ringbuf_event_parser_fuzz.cpp) still contains the comment "We don't have a standalone parser function yet" and only `memcpy`s into `kwatch_event` before reading a flag bit.

7. Medium: README/demo media still do not satisfy the Audience-A requirements in `R6.1` / `R6.5`.
   Evidence: [README.md](README.md) only embeds `docs/media/demo.svg`; it does not reference a second `top` animation. [docs/media/demo.svg](docs/media/demo.svg) is a static placeholder pointing readers to `demo.cast`, not an autoplaying animated SVG. `docs/media/top.cast` exists, but no corresponding rendered `top.svg` is embedded anywhere.

8. Medium: `recent_events` truncation is silent, so the TUI header under-reports event loss.
   Evidence: [src/cli/commands/top.cpp](src/cli/commands/top.cpp) drops the oldest element when `recent_events.size() > 50`, but the displayed drop counter only comes from [src/bpf/ringbuf.cpp](src/bpf/ringbuf.cpp), where it increments on `ring_buffer__poll()` error paths rather than on UI-buffer eviction.

9. Low: `prompt_input()` uses unbounded `getstr()` with a fixed 256-byte stack buffer.
   Evidence: [src/tui/app.cpp](src/tui/app.cpp). `getnstr(buf, sizeof(buf) - 1)` would remove the overflow footgun and likely silence `clang-tidy`.

10. Low: The Firewall view's delete path linearly scans the LPM trie to resolve the selected row.
    Evidence: [src/tui/app.cpp](src/tui/app.cpp). This is acceptable with the current map cap (`1024`), but deserves an explicit comment because the complexity is hidden in UI code.

11. Low: The TUI demo view hard-codes demo parameters and does not expose any configuration surface.
    Evidence: [src/tui/app.cpp](src/tui/app.cpp) fixes `target_ip=127.0.0.1`, `rate_pps=50`, and `duration_s=5`. This is a UX/product gap; it is not as clear-cut a PRD violation as the items above, because `R5.9` only requires menu-driven launch.

## Not Added

1. Stale: "Working tree is still uncommitted."
   Evidence: `git status --short` is clean and `git log --oneline -1` currently reports `0e7dbd4 fix: resolve PRD compliance gaps and TUI interactive features`.
