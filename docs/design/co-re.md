# Compile Once, Run Everywhere (CO-RE)

K-Watch utilizes BPF CO-RE to maintain portability across different Linux kernel versions.

## Why it matters
Historically, BPF programs were compiled against the specific headers of the target kernel. This meant a tool built for Ubuntu 20.04 might crash on 22.04 if a kernel struct field moved or changed size.

## Implementation
1. **vmlinux.h**: We do NOT commit `vmlinux.h` to Git. It is generated at build time using `bpftool btf dump`.
2. **Relocations**: We use CO-RE field-existence relocations (`bpf_core_field_exists`) for XDP context compatibility. Packet headers are wire-format data, not kernel structs, so they are parsed with verifier-bounded packet reads rather than `BPF_CORE_READ`.
3. **Detection**: During `bpf_object__load`, `libbpf` uses the BTF data on the host system (`/sys/kernel/btf/vmlinux`) to rewrite the program's memory offsets to match the running kernel exactly.

This ensures K-Watch remains a stable, single-binary distribution.
