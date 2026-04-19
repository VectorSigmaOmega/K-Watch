# K-Watch: eBPF Kernel Observability Engine

K-Watch is a high-performance network monitoring and filtering tool powered by eBPF (XDP). It injects code directly into the Linux kernel to process packets at the driver level, before they reach the CPU's network stack.

## Architecture

1.  **Kernel-Space (eBPF/XDP):**
    *   **Hook:** Attached to the XDP (Express Data Path) hook of a network interface.
    *   **Parser:** Decodes Ethernet and IPv4 headers to identify protocols (TCP, UDP, ICMP).
    *   **Filtering (Kill-Switch):** Checks every source IP against a BPF Hash Map (`blacklist`). If a match is found, the packet is dropped immediately (`XDP_DROP`).
    *   **Metrics:** Increments counters in a BPF Hash Map (`pkt_counts`) based on the IP protocol.

2.  **User-Space (C++/libbpf):**
    *   **Loader:** Uses `libbpf` and the generated BPF skeleton to load and attach the program to an interface.
    *   **Control:** Allows users to populate the `blacklist` map via command-line arguments.
    *   **Dashboard:** Periodically reads the `pkt_counts` map and displays live statistics in the terminal.

## How to Run

### Prerequisites
*   Ubuntu 24.04 (or similar Linux distro)
*   `clang`, `llvm`, `libbpf-dev`, `libelf-dev`
*   `bpftool` (for skeleton generation)

### Build
```bash
make
```

### Run Statistics Monitor
Attach K-Watch to an interface (e.g., `lo` or `eth0`):
```bash
sudo ./kwatch lo
```

### Use the Kill-Switch (Block an IP)
To block a specific IP address:
```bash
sudo ./kwatch lo --block 1.2.3.4
```

### Testing
1.  Run `sudo ./kwatch lo` in one terminal.
2.  Generate traffic in another terminal: `ping 127.0.0.1`.
3.  Observe the ICMP counts increasing in K-Watch.
4.  Try blocking your own loopback (caution: might disrupt local services): `sudo ./kwatch lo --block 127.0.0.1`.

## Files
*   `src/kwatch.bpf.c`: The eBPF kernel code.
*   `src/kwatch.cpp`: The C++ user-space application.
*   `src/vmlinux.h`: Kernel type definitions (generated).
*   `Makefile`: Build automation.
