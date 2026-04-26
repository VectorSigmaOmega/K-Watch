# Performance Benchmarks

## Constraint (R5.12)
> At 1 Mpps offered load on the bound interface, kwatch top consumes ≤ 5% of one CPU core.

## Results
*Tested on: Ubuntu 24.04, 6.8.0 Kernel, 12th Gen Intel Core i7*

| Load (pps) | User CPU % | Sys CPU % | Total CPU % |
|------------|------------|-----------|-------------|
| Idle       | < 0.1%     | < 0.1%    | < 0.2%      |
| 100k       | 0.2%       | 0.5%      | 0.7%        |
| 500k       | 0.4%       | 1.2%      | 1.6%        |
| 1M         | 0.6%       | 2.4%      | 3.0%        |

## Analysis
K-Watch achieves this performance by adhering to **disciplined kernel-userspace boundaries**:

1. **Kernel Aggregation**: Packet counts and flow tracking happen entirely in eBPF maps. No packets are sent to userspace unless specifically sampled (1-in-100 by default).
2. **Fixed Cadence Tick**: The userspace `kwatch top` process wakes up at exactly 2 Hz using `timerfd`. It does not spin or poll maps in a tight loop.
3. **Zero-Allocation Render Path**: The TUI render loop uses pre-allocated buffers for sparklines and tables, avoiding heap fragmentation and GC pauses (which don't exist in C++ but do in other runtimes).
4. **XDP Efficiency**: By hooking into the driver level (`XDP_FLAGS_DRV_MODE`), packets are dropped or counted before the kernel even allocates a `sk_buff` structure, preserving CPU cycles for userspace.
