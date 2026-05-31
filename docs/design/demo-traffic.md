# Demo Traffic

K-Watch includes a small demo surface so reviewers can prove the dataplane without installing external traffic generators.

Required v1.0 scenarios:

- `kwatch demo ping-flood --target 127.0.0.1 --duration 2s`
- `kwatch demo udp-storm --target 127.0.0.1 --duration 2s`

Rules:

- Demos must generate traffic from inside the binary using sockets.
- Demos must be bounded by duration and rate.
- Demos must refuse non-loopback targets unless `--i-know-what-im-doing` is passed.
- Demos are proof traffic, not benchmark tooling.
- `syn-flood` may exist as an experimental scenario, but SYN-flood detection and auto-blocking are not v1.0 requirements.
