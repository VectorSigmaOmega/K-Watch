# XDP Attach Modes

K-Watch supports three XDP attachment modes, prioritizing performance while maintaining compatibility.

## Priority Order
1. **Driver Mode (`DRV`)**: The BPF program runs in the network driver's receive path. Highest performance.
2. **SKB Mode (`SKB`)**: Also known as Generic XDP. Runs in the kernel's generic networking path. Compatible with all interfaces (including loopback and virtual ethernet) but slower.
3. **Hardware Mode (`HW`)**: Offloaded directly to the NIC hardware. (Rarely used in virtualized environments).

## Fallback Logic
By default, `kwatch run` attempts `DRV` mode first. If the driver does not support XDP, it transparently falls back to `SKB` mode. This ensures that `kwatch run lo` (loopback) works out of the box while still providing high-performance on physical NICs.
