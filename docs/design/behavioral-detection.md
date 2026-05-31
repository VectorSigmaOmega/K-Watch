# Behavioral Detection - Future Enhancement

Behavioral SYN-flood detection is not required for the focused v1.0 portfolio scope. The required project demonstrates packet parsing, counters, sampled events, CIDR blocking, and safe resource lifecycle.

If behavioral detection is restored as a post-v1.0 feature, it should be specified and tested separately:

- Aggregate SYN and ACK counts per source IP.
- Keep auto-blocking off by default.
- Require explicit `--auto-block` before modifying the blacklist automatically.
- Add a bounded auto-block TTL.
- Document false-positive cases such as asymmetric routing, SYN cookies, spoofed sources, and legitimate parallel connections.
- Use the built-in detection path in integration tests rather than substituting unrelated traffic.

Until then, any existing flow-state or SYN-counting code is implementation detail or experimental work, not a release blocker.
