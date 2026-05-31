# K-Watch

K-Watch is a small C++20/libbpf XDP tool for observing IPv4 traffic, generating safe loopback demo traffic, and controlling an in-memory CIDR blacklist. It is built as a Linux networking portfolio project: native binary, generated CO-RE artifacts, BPF maps for kernel/userspace state, and RAII ownership of kernel resources. It is not a production IDS, WAF, SIEM, benchmark tool, or persistent firewall.

## Architecture

See [docs/architecture.md](docs/architecture.md).

NIC -> XDP parser/filter -> BPF maps -> ring buffer -> C++ CLI/demo traffic

## Quickstart

Start the observer on loopback:

```bash
sudo ./build/kwatch run lo
```

## Build

```bash
cmake -B build
cmake --build build
```

Emit NDJSON instead of text:

```bash
sudo ./build/kwatch run lo --json
```

In another terminal, generate bounded loopback traffic:

```bash
sudo ./build/kwatch demo ping-flood --target 127.0.0.1 --duration 2s
sudo ./build/kwatch demo udp-storm --target 127.0.0.1 --duration 2s
```

In another terminal, inspect counters while `run` is active:

```bash
sudo ./build/kwatch stats lo
```

Add and remove CIDR blacklist entries while `run` is active:

```bash
sudo ./build/kwatch block lo 127.0.0.1/32
sudo ./build/kwatch list lo
sudo ./build/kwatch unblock lo 127.0.0.1/32
```

Detach any XDP program from an interface:

```bash
sudo ./build/kwatch detach lo
```

## Core Features

- XDP parser for Ethernet, one VLAN tag, IPv4, TCP, UDP, and ICMP.
- Count-only sentinel handling for IPv6 and ARP.
- `pkt_counts` protocol counter map.
- CIDR-capable `blacklist` map using `BPF_MAP_TYPE_LPM_TRIE`.
- Sampled packet metadata through a BPF ring buffer.
- Safe built-in ICMP and UDP loopback demo traffic.
- C++ RAII wrappers for libbpf skeletons, XDP links, ring buffers, and file descriptors.
- Generated `vmlinux.h`, BPF object, and skeleton headers.
- Single native binary; no web UI, Node.js service, or second runtime.

## Verify

```bash
cmake --build build
./build/kwatch_tests
find src bpf tests \( -path 'tests/vendored' -o -path 'tests/vendored/*' \) -prune -o \
  \( -name '*.cpp' -o -name '*.c' -o -name '*.h' \) -print | \
  xargs clang-format --Werror --dry-run
```

Privileged integration tests are under `tests/integration/` and assume Linux with BTF and permissions to create a veth/netns test fixture.

## Documentation

- [Architecture](docs/architecture.md)
- [Exit Codes](docs/exit-codes.md)
- [CO-RE Notes](docs/design/co-re.md)
- [XDP Attach Modes](docs/design/xdp-attach-modes.md)
- [LPM Blacklist](docs/design/lpm-blacklist.md)
- [Demo Traffic](docs/design/demo-traffic.md)

## Optional Work

The repository may contain experimental TUI, SYN-flood detection, auto-blocking, fuzzing, or benchmark work. Those are future enhancements and are not required for the focused portfolio scope in [PRD.md](PRD.md).

The default build does not include the ncurses TUI. That remains an optional surface for a separate `-DKWATCH_BUILD_TUI=ON` build.

## License

MIT
