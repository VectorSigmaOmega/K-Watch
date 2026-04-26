# LPM Blacklist (CIDR Support)

Instead of a simple Hash Map, K-Watch uses `BPF_MAP_TYPE_LPM_TRIE` for its blacklist.

## Why LPM?
Longest Prefix Match (LPM) allows us to block entire networks (e.g., `10.0.0.0/8`) with a single map entry. The kernel handles the bit-mask matching efficiently in O(1) or O(log N) time, ensuring that even with thousands of rules, packet latency remains minimal.

## Usage
Rules can be added via `kwatch block <iface> <cidr>`.
Example: `sudo kwatch block eth0 192.168.1.0/24`
