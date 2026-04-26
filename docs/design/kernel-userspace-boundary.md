# Kernel-Userspace Boundary

K-Watch follows a "Thin Userspace, Thick Kernel" philosophy.

## Principles
1. **Aggregation in Kernel**: Calculating PPS, protocol counts, and connection state happens in BPF maps. Userspace never sees the raw packet stream.
2. **Fixed Wake-ups**: Userspace is event-driven for high-priority ringbuf events, but throttled to 2 Hz for statistics. This prevents userspace from competing for CPU with the kernel's packet processing.
3. **Shared Memory**: We use BPF Maps as the primary IPC. Userspace reads from maps, and the kernel reacts to map changes (e.g., the blacklist).
