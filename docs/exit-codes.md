# Exit Codes

K-Watch uses a small set of sysexits-style codes:

| Code | Label | Meaning |
|------|-------|---------|
| 0 | SUCCESS | Command completed successfully. |
| 64 | EX_USAGE | Invalid command-line usage. |
| 65 | EX_DATAERR | Invalid data, invalid interface, invalid CIDR, or no active map state for the requested interface. |
| 69 | EX_UNAVAILABLE | Kernel feature unavailable, including missing BTF or unsupported XDP attach. |
| 77 | EX_NOPERM | Insufficient permission. The error should name root, `CAP_BPF`, `CAP_NET_ADMIN`, or `CAP_NET_RAW`. |
| 125 | EX_SOFTWARE | Internal error or unexpected OS/libbpf failure. |
