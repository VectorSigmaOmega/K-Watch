# Performance Notes

Formal packet-rate benchmarking is outside the focused v1.0 portfolio scope.

The required performance posture is qualitative and code-reviewable:

- Packet parsing, blacklist lookup, and protocol counters happen in XDP.
- Userspace receives sampled metadata through a ring buffer, not full packet streams.
- `stats`, `block`, `unblock`, and `list` operate through BPF maps.
- The tool should avoid busy loops in normal operation.

Future benchmark work may add pktgen/veth measurements and CPU profiles, but unverified throughput or CPU-percentage claims should not be used as release criteria.
