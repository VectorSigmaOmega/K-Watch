# Exit Codes

K-Watch uses the following exit codes to indicate specific failure modes:

| Code | Label | Meaning |
|------|-------|---------|
| 0    | SUCCESS | Process exited normally. |
| 64   | EX_USAGE | Incorrect command line arguments. |
| 65   | EX_DATAERR | Invalid data (e.g. interface not found, map open failure). |
| 69   | EX_UNAVAILABLE | Kernel feature unavailable (No BTF, XDP not supported). |
| 77   | EX_NOPERM | Insufficient permissions (Requires CAP_BPF, CAP_NET_ADMIN, or root). |
| 124  | TIMEOUT | Operation timed out (used in tests/demos). |
| 125  | EX_SOFTWARE | Internal logic error or OS syscall failure. |
