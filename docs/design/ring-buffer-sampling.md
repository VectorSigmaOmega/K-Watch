# Ring Buffer Sampling

Streaming every single packet to userspace would overwhelm the system and defeat the purpose of eBPF. K-Watch uses an "Interest-Based Sampling" policy.

## The Policy
1. **First-Packet**: The very first packet of any new 4-tuple flow is ALWAYS sent to userspace.
2. **Statistical Sampling**: Subsequent packets in the same flow are sampled at a rate of 1-in-N (default N=100).
3. **Thresholds**: N is configurable via `--sample-n`, which is written into the BPF program's `volatile const __u32 sample_n` before load.

This keeps `kwatch run` useful for live observation without turning userspace into a per-packet processing path.
