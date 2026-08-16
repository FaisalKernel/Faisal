# FAISAL M102 open-source integration design

## Decision

FAISAL will not copy an entire external agent framework or memory database into the Linux kernel. The reviewed repositories occupy different boundaries:

| Candidate | Verified strength | FAISAL decision |
|---|---|---|
| Engram | Go persistent memory service using SQLite/FTS5, MCP, CLI, HTTP, and TUI; MIT license | Userspace memory interoperability reference only; do not treat records as verified truth or kernel authority |
| Mem0 | Multi-level userspace agent memory layer; Apache-2.0 repository | Semantic-memory adapter reference only; preserve FAISAL provenance, freshness, conflict, and promotion gates |
| Letta | Stateful-agent runtime and memory concepts; current code moved to `letta-code`, old server archived | Architectural reference; do not use archived server as a dependency |
| OpenSandbox | Sandbox protocol, egress policy, credential vault, runtime abstraction, gVisor/Kata/Firecracker options, signed image guidance; Apache-2.0 | Primary M102 protocol and policy reference; integrate through a narrow trusted supervisor |
| Anthropic sandbox-runtime | Local OS-level filesystem/network/socket restrictions and proxy-mediated allow-list egress; Apache-2.0 research preview | Primary network-policy reference; retain only policy ideas and test cases, not an unverified runtime dependency |
| gVisor | Userspace application kernel and OCI runtime reducing host-kernel surface | Optional M102 backend selected by policy after compatibility and overhead tests |
| Firecracker | KVM microVM with minimal device model and strong isolation boundary | Optional high-risk backend; requires KVM, image verification, resource policy, and a separate supervisor |

## Selected implementation

M102 will first implement a small FAISAL-native **network-deny nondeterministic adapter**. It will execute a fixed, trusted program specification—not arbitrary model-generated shell text—under a user/network namespace, Landlock scratch scope, no-new-privileges, bounded output capture, and M99/M100-compatible authority and receipt gates. Network access is denied by default; controlled proxy egress is deferred until a separate policy compiler and independent verifier exist.

This gives FAISAL a measurable and auditable first integration without importing a large platform, trusting external metadata, or weakening M100’s effect contract. The external projects remain optional backend references. A later adapter may delegate to OpenSandbox, gVisor, or Firecracker only when the backend identity, image digest, policy digest, authority lease, output digest, and verification receipt are all bound.

## Non-negotiable boundaries

The model never authorizes the program. A trusted registry maps a tool identity to an implementation digest, executable path, fixed argument schema, network mode, scratch scope, and risk class. The broker validates M99 invocation state, revocation generation, mission/authority binding, and input digest before launch. The child cannot create unrestricted network access, write outside its scoped directory, or escape the no-new-privileges boundary. Ambiguous termination is never automatically retried.

## References

[1]: https://github.com/Gentleman-Programming/engram — Engram.

[2]: https://github.com/mem0ai/mem0 — Mem0.

[3]: https://github.com/letta-ai/letta — Letta project landing page and archive notice.

[4]: https://github.com/opensandbox-group/OpenSandbox — OpenSandbox.

[5]: https://github.com/anthropic-experimental/sandbox-runtime — Anthropic sandbox-runtime.

[6]: https://github.com/google/gvisor — gVisor.

[7]: https://github.com/firecracker-microvm/firecracker — Firecracker.
