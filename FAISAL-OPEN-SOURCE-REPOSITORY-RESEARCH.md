# FAISAL open-source repository research checkpoint

**Date accessed:** 2026-08-16

## Engram

Primary source: https://github.com/Gentleman-Programming/engram

Engram describes itself as a persistent memory system for AI coding agents. The repository page identifies an agent-agnostic Go binary using SQLite and FTS5, with CLI, HTTP API, MCP server, and TUI interfaces. The repository states that MCP transport is stdio-only and does not expose a TCP MCP endpoint. GitHub showed active development signals at access time, including 393 commits, 151 issues, 35 pull requests, 6k stars, and a recent `main` branch commit. These activity counts are observations, not quality or security proof.

License source: https://github.com/Gentleman-Programming/engram/blob/main/LICENSE

The repository’s LICENSE page identifies the MIT License, copyright 2026 Alan Buscaglia, and requires preservation of copyright and license notices. It permits modification and distribution subject to those conditions. FAISAL must preserve the license if code is reused; a clean-room protocol adapter is preferable to copying code into the kernel.

## Initial fit assessment

Engram is a candidate for a **userspace episodic-memory adapter or interoperability reference**, not a kernel component. Its SQLite/FTS5 storage and agent-facing APIs overlap conceptually with FAISAL’s existing persistent-memory and experience services, but it does not provide kernel primitives, capability enforcement, cryptographic provenance, causal authority, or exactly-once external-effect semantics. Its HTTP API and cloud integration require separate security review; the stdio-only MCP boundary is the safer integration surface.

FAISAL must not treat Engram’s stored memories as verified truth, model retraining, self-awareness, or kernel authority. Any integration must bind records to FAISAL identity, task lineage, capability scope, source provenance, freshness, conflict state, and explicit authorization. The first safe action is comparative inspection and an import/export adapter test, not direct deployment or code copying.

## Candidate repositories found for follow-up verification

Search results identified Mem0 (`https://github.com/mem0ai/mem0`) as an agent memory layer, Letta as a stateful-agent framework, LangGraph as an orchestration framework, and curated sandbox/runtime-security repositories. These are leads only; no implementation or quality claim is made until each primary repository, license, dependency graph, security policy, maintenance status, and benchmark is inspected.

## References

[1]: https://github.com/Gentleman-Programming/engram — Engram repository.

[2]: https://github.com/Gentleman-Programming/engram/blob/main/LICENSE — Engram license.

[3]: https://github.com/mem0ai/mem0 — Mem0 repository lead.

## Mem0

Primary source: https://github.com/mem0ai/mem0

Mem0 presents itself as a universal memory layer for AI agents with multi-level user, session, and agent state, cross-platform SDKs, and a managed-service option. GitHub identifies the repository as Apache-2.0 licensed and shows a large, active repository with many releases and ongoing changes. These repository activity signals do not prove correctness or suitability.

Mem0 is a userspace memory-layer candidate, not a kernel primitive. It may inform FAISAL’s semantic-memory adapter and evaluation design, but it does not replace FAISAL’s kernel-bound identity, capability, provenance, freshness, conflict, corruption-replay, or authority controls. Any integration should use a narrow import/export protocol and treat Mem0 records as untrusted external memory until FAISAL validation promotes them.

## References

[4]: https://github.com/mem0ai/mem0 — Mem0 primary repository.

## Letta

Primary source: https://github.com/letta-ai/letta

The repository page describes Letta as a platform for stateful agents with advanced memory. It explicitly states that the current source lives in `letta-ai/letta-code`, while the `letta` repository is now a landing page and the older V1 server is preserved on an archive branch. The page says the archived V1 source is unsupported and receives no fixes or security updates. The repository identifies an Apache-2.0 license and shows current activity, releases, and a large historical commit base.

Letta is therefore useful as an architectural reference for stateful agent runtime and memory semantics, but the archived repository is not an appropriate direct dependency. Any future inspection must target `letta-ai/letta-code`. It remains userspace and does not provide FAISAL kernel authorization, provenance, resource enforcement, or deterministic effect verification.

## References

[5]: https://github.com/letta-ai/letta — Letta repository and archive notice.

## OpenSandbox

Primary source: https://github.com/opensandbox-group/OpenSandbox

OpenSandbox describes a general-purpose sandbox platform for AI applications with multi-language SDKs, sandbox lifecycle and execution APIs, Docker/Kubernetes runtimes, command/filesystem/code-interpreter environments, browser and desktop examples, network-policy components, credential-vault support, and strong-isolation options including gVisor, Kata Containers, and Firecracker microVMs. The repository README states that official release images are keylessly signed with Cosign and include provenance attestations, with digest pinning and release-verification guidance. GitHub identifies an Apache-2.0 license and active development signals.

OpenSandbox is the strongest candidate found so far for a **M102 userspace nondeterministic adapter integration reference**, especially its sandbox protocol, egress policy, credential injection, and runtime abstraction. It is not a replacement for M100: FAISAL still needs its own capability-scoped effect capsule, authority binding, provenance, revocation, ambiguity semantics, and independent verification. OpenSandbox’s HTTP control plane and credential-vault paths require threat-model review before use; production images would need digest and signature verification. No code has been copied or executed.

## References

[6]: https://github.com/opensandbox-group/OpenSandbox — OpenSandbox primary repository.

## Anthropic sandbox-runtime (srt)

Primary source: https://github.com/anthropic-experimental/sandbox-runtime

The repository describes `srt` as a lightweight sandboxing tool for arbitrary processes without requiring a container. It uses native OS primitives: `sandbox-exec` on macOS, bubblewrap on Linux, and a dedicated Windows account plus Windows Filtering Platform rules. It supports filesystem, network, and Unix-socket restrictions and is designed for agents, local MCP servers, shell commands, and arbitrary processes. The Linux model removes the sandbox network namespace and routes traffic through host proxies exposed through Unix sockets; the README describes default-deny network policy and allow-only writes. The repository identifies an Apache-2.0 license and labels itself a beta research preview whose APIs and configuration may evolve.

Srt is a valuable **design reference for M102 network isolation**, especially its dual filesystem/network boundary and proxy-mediated egress model. It should not replace M100 effect receipts or FAISAL authority. The Unix-socket proxy becomes a high-risk trusted boundary requiring capability binding, destination policy, provenance, response sanitization, timeout/cancellation, and independent verification. No code has been copied or executed.

## References

[7]: https://github.com/anthropic-experimental/sandbox-runtime — Anthropic sandbox-runtime primary repository.

## Firecracker

Primary source: https://github.com/firecracker-microvm/firecracker

Firecracker is an open-source VMM using Linux KVM to run lightweight microVMs. Its repository describes a minimalist device and guest-facing surface intended to reduce attack surface and memory footprint while retaining hardware-virtualization isolation and container-like startup characteristics. The project emphasizes that safe multi-tenant security depends on a correctly configured Linux host and provides production host setup and security-policy documentation. It also states that performance specifications are continuously tested in CI.

Firecracker is the strongest high-isolation backend candidate for high-risk M102 effects, but it is not a direct FAISAL kernel enhancement. It introduces KVM/VMM/guest-image lifecycle complexity and cannot replace M100 receipts or trusted authority. The correct FAISAL integration is a supervisor-selected sandbox backend with digest-pinned images, host-policy verification, resource budgets, capability-bound communication, and receipt binding; no Firecracker code is copied into the kernel at this stage.

## References

[8]: https://github.com/firecracker-microvm/firecracker — Firecracker primary repository.

## gVisor

Primary source: https://github.com/google/gvisor

gVisor describes itself as a userspace application kernel written in Go that implements a Linux-like interface and limits the host-kernel surface accessible to applications. Its OCI `runsc` runtime integrates with Docker and Kubernetes. The repository explicitly distinguishes gVisor from syscall filters, wrappers around Linux isolation primitives, and conventional VMs. It presents gVisor as a third isolation approach with lower resource footprint and faster startup than full VMs, while reducing shared-kernel exposure.

gVisor is a plausible M102 backend for workloads needing more isolation than a direct process sandbox but less boundary weight than a microVM. It is not a kernel patch and should remain an external runtime selected by policy. FAISAL must measure startup, syscall compatibility, resource overhead, and escape-resistance assumptions rather than adopting the project’s positioning as a benchmark result. No code has been copied or executed.

## References

[9]: https://github.com/google/gvisor — gVisor primary repository.
