# K-Watch Threat Model

K-Watch is a privileged demonstration tool. It loads an XDP program, owns BPF maps, and can drop packets that match the active CIDR blacklist.

## Assets

- Host network availability.
- Loaded XDP program and BPF maps.
- Blacklist contents.
- Terminal/log output used by the operator.

## In Scope

- Malformed or hostile network packets reaching the XDP parser.
- Accidental broad CIDR blacklist entries.
- Resource leaks that leave XDP attached after `kwatch run` exits.
- Permission failures when the binary is run without the required capabilities.
- Demo traffic accidentally targeting non-loopback addresses.

## Out of Scope

- Kernel vulnerabilities.
- Malicious root users.
- Persistent policy storage.
- Production intrusion detection or automatic mitigation.
- Traffic generation for benchmarking or stress testing arbitrary networks.

## Defenses

- The blacklist is explicit operator-controlled state, not automatic policy.
- CIDR matching uses an LPM trie with bounded entries.
- The XDP link and BPF resources are owned by C++ RAII wrappers.
- Permission failures should exit 77 and name the needed privilege.
- Demo traffic refuses non-loopback targets unless the operator passes an explicit override.
- `detach` is idempotent so recovery is simple if an operator wants to remove any XDP program from an interface.

K-Watch is suitable as a systems-programming portfolio project. It should not be deployed as the sole protection for a production network.
