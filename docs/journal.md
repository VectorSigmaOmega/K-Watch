# Project Journal

This journal is intentionally short after the 2026-04-30 scope reset.

Earlier drafts tried to make K-Watch a larger product: TUI, SYN-flood detection, auto-blocking, performance claims, fuzzing, coverage, and broader CI. That made reviews behave like whack-a-mole because every optional surface became another required acceptance gate.

The current direction is narrower:

- Finish the core XDP/libbpf CLI.
- Keep ICMP and UDP loopback demos as the required proof traffic.
- Keep generated BPF artifacts out of git.
- Make map lifecycle and exit codes correct.
- Prove the required behavior with unit and privileged integration tests.
- Treat TUI, behavioral detection, and benchmarks as future enhancements.

The success criterion is no longer "all impressive ideas are implemented." It is "the required low-level tool is correct, buildable, documented, and easy for a Linux networking reviewer to trust."
