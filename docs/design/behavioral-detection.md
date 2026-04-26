# Behavioral Detection Design

K-Watch implements a lightweight behavioral detection engine primarily focused on connection-oriented abuse (e.g., SYN floods).

## SYN Flood Detection

The detection operates across the BPF and Userspace boundary:

1. **Kernel (`flow_state` LRU Map)**:
   The XDP program observes TCP traffic and records `syn_count` and `ack_count` for each 4-tuple flow. 
   When a new flow is detected (e.g., the first SYN), a `kwatch_event` is pushed to the ring buffer. Since an attacker typically randomizes source ports or targets many different destination ports in a SYN flood, every packet in the flood constitutes a "new flow" and emits a ring buffer event.

2. **Userspace (`FlowTracker`)**:
   The userspace daemon drains these `kwatch_event` structures. It aggregates the SYN and ACK counts per source IP (`ip_stats` hash map).
   During the 2 Hz tick, it checks if an IP's SYN count has exceeded `--syn-threshold` (default 100) within `--syn-window` (default 10s) while having zero ACKs.

### Auto-Block Mechanism
If `--auto-block` is enabled, the IP is automatically inserted into the LPM-trie blacklist with a TTL (`--auto-block-ttl`, default 300s). The IP is unblocked automatically when the TTL expires.

### False Positives
- **SYN Cookies**: When the kernel is under SYN-flood load, it may issue SYN-cookies and drop state. If the client responds with an ACK, K-Watch will see it and register it, preventing the IP from being flagged as purely malicious.
- **Asymmetric Routing**: If K-Watch only observes inbound traffic, but outbound ACKs are routed differently, legitimate IPs might appear to have 0 ACKs. Operators in asymmetric networks should keep `--auto-block` OFF and use K-Watch strictly for observation.
- **Legitimate Parallel Connections**: Browsers opening many parallel connections. The default threshold (100) is set well above typical browser concurrency limits.