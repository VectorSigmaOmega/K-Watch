# K-Watch Threat Model

K-Watch operates at the intersection of kernel-space packet processing and userspace observation. This document outlines the perceived threats and the mitigation strategies implemented in v1.0.

## 1. Asset Inventory
*   **Primary Asset:** Kernel stability and network availability.
*   **Secondary Asset:** BPF maps containing blacklist and flow state.
*   **Tertiary Asset:** Userspace dashboard (TUI).

## 2. Trust Boundaries
*   **Kernel Boundary:** XDP program (privileged) vs. NIC (untrusted input).
*   **Userspace Boundary:** Daemon (privileged) vs. CLI (standard user).

## 3. Threat Analysis

### T1: Denial of Service (DoS) via Map Exhaustion
*   **Vector:** A flood of unique source IPs filling the `flow_state` map.
*   **Mitigation:** `flow_state` is implemented as an `LRU_HASH` (R4.4). The kernel automatically evicts the oldest flows to make room for new ones, ensuring the tool remains responsive under massive flow storms.

### T2: False Positive Auto-Blocking
*   **Vector:** Spoofed traffic tricking the SYN-flood detector into blocking legitimate users.
*   **Mitigation:**
    *   `--auto-block` defaults to **OFF** (R4.3).
    *   Thresholds (SYN/ACK ratio) are configurable (R4.2).
    *   Auto-blocks have a mandatory TTL (R4.5) to ensure accidental blocks are temporary.

### T3: Resource Leaks in Kernel
*   **Vector:** K-Watch crashes and leaves the XDP program attached, preventing other tools from binding or causing "orphan" packet processing.
*   **Mitigation:** Mandatory use of `bpf_link` (R3.3). The kernel automatically detaches the program when the userspace file descriptor closes.

### T4: Privilege Escalation
*   **Vector:** Malicious user injecting entries into the BPF map via the CLI.
*   **Mitigation:** Standard Linux permissions apply to the BPF filesystem (`/sys/fs/bpf/kwatch_*`). Only users with `CAP_BPF` or `root` can modify the maps.

## 4. Safety Summary
K-Watch is designed as a *demonstration* tool. It prioritizes system safety (RAII, `bpf_link`) and visibility over production-grade hardening. It should not be used as the sole defense for a mission-critical network.
