# Ring Buffer Sampling

Streaming every single packet to userspace would overwhelm the system and defeat the purpose of eBPF. K-Watch uses an "Interest-Based Sampling" policy.

## The Policy
1. **First-Packet**: The very first packet of any new 4-tuple flow is ALWAYS sent to userspace.
2. **Statistical Sampling**: Subsequent packets in the same flow are sampled at a rate of 1-in-N (default N=100).
3. **Thresholds**: N is configurable via the `--sample-n` internal volatile const.

This allows us to maintain a live "Recent Events" log in the TUI without sacrificing performance under high-volume flood scenarios.
