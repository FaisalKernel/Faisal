# FAISAL

> **A Linux-derived kernel and evidence-bound control plane for autonomous workloads.**

FAISAL is an open-source Linux-derived platform for developers building agent runtimes, AI infrastructure, secure tool brokers, robotics-adjacent control systems, and long-lived autonomous services. Its purpose is not to put an AI model in the kernel. Its purpose is to provide **deterministic operating-system primitives and reviewable control-plane contracts** for workloads that need explicit authority, traceability, recovery, and release discipline.

> **Core rule:** model output may inform a decision; it never authorizes a kernel action, tool call, hardware claim, or production release by itself.

## Project status

| Field | Current public status |
|---|---|
| Release line | Linux 7.2 forward-port candidate |
| ABI | 47 |
| Source state | Public, curated kernel and control-plane tree |
| Production authority | **False / fail-closed** |
| License model | Linux kernel model: `GPL-2.0 WITH Linux-syscall-note` in `COPYING`, plus file-level SPDX identifiers |
| Production qualification | Independent builder reproduction, operator signing, physical hardware qualification, external security review, and live multihost qualification are still required |

FAISAL is **not represented as production-ready**. A local build, a QEMU result, a regression pass, an evidence record, or provider metadata is not a production authorization.

## Why FAISAL

Linux already provides mature process, memory, scheduling, IPC, filesystem, network, and device foundations. Autonomous workloads add a different class of operational questions:

- Which component is authorized to perform an action, for which intent, and for how long?
- Can a tool invocation, memory write, routing decision, checkpoint, or recovery action be traced to explicit policy and evidence?
- Can a failed workload be contained, inspected, and recovered without treating a model response as privileged authority?
- Can a release remain blocked until independent evidence exists, even when local validation passes?

FAISAL extends the Linux-derived platform around those questions. It favors bounded authority and evidence receipts over implicit trust.

## Architecture

```text
┌──────────────────────────────────────────────────────────────────────┐
│ Applications, agent runtimes, model servers, MCP clients, robotics   │
│ stacks, and domain services                                           │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ FAISAL userspace services                                             │
│ Objective supervision · policy · durable state · recovery · rollout   │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Evidence-bound control-plane contracts                                │
│ Intent · capability · memory · routing · tools · checkpoint · trace   │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Linux-derived kernel primitives / ABI 47                              │
│ Process · memory · scheduling · IPC · device boundaries · authority   │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ CPU · memory · storage · network · devices · qualified hardware proof │
└──────────────────────────────────────────────────────────────────────┘
```

The design keeps complex reasoning, model inference, application policy, and fast-changing provider integrations in **userspace**. The kernel remains focused on secure, deterministic, inspectable primitives and lifecycle boundaries.

## Core control-plane surfaces

| Surface | What it provides | Why it matters to developers |
|---|---|---|
| **Intent-bound authority leases** | Bounded use tied to intent, capability, lineage, expiry, revocation, and session conditions. | Lets a service express least-privilege authority rather than translating an agent result directly into permission. |
| **Capability delegation and provenance** | Scoped delegation and provenance-aware authorization checks. | Makes authority transfer inspectable and supports denial of stale, cross-scope, or untrusted requests. |
| **Memory admission and receipts** | Read/write admission, receipt evidence, intervention, and cache-residency control surfaces. | Treats persistent agent state as governed state rather than an unbounded model memory store. |
| **Checkpoint and recovery fences** | Side-effect boundaries and recovery-oriented checkpoint records. | Helps services build restart, rollback, and recovery flows around explicit supervisor review. |
| **Model routing and fallback evidence** | Provider-neutral route metadata and policy-gated routing receipts. | Separates a routing decision record from any claim that a specific provider actually executed a request. |
| **Trace conformance and certification** | Deterministic lineage validation and rejection of malformed or untrusted observations. | Gives observability pipelines a contract for provenance and conformance checks. |
| **MCP tool-contract controls** | Tool-definition and permitted data-flow admission checks. | Creates a policy surface for tools before provider-specific execution is asserted. |
| **Hardware qualification contracts** | Requirements for discovery, isolation, transport, accounting, power, and physical evidence. | Prevents a configuration or metadata-only environment from being described as validated accelerator hardware. |

## Developer integration model

FAISAL is designed to be integrated from userspace outward.

1. **Run your application or agent runtime in userspace.** Model servers, browser/tool clients, robotics stacks, schedulers, and application logic remain outside kernel space.
2. **Identify the authority boundary.** Map privileged tools, persistent-state writes, device access, network egress, or deployment operations to an explicit capability and intent policy.
3. **Use receipts where decisions matter.** Record intent, routing, admission, tool definition, checkpoint, and trace evidence at the points where review, debugging, recovery, or release gating matters.
4. **Build recovery into the design.** Treat checkpoint and rollback state as bounded recovery context for an approved supervisor—not as unrestricted autonomous mutation.
5. **Qualify real hardware separately.** Keep provider-neutral contracts in code, then connect them to real devices only when device, isolation, transport, telemetry, and power evidence is observed.
6. **Keep release approval external.** Use local validation as evidence input; do not turn it into independent production authority.

## Security and authority model

FAISAL’s security posture is based on explicit boundaries rather than intelligence claims. The system does not equate a model answer with authorization, stored experience with model retraining, introspection with consciousness, compilation with completion, provider metadata with hardware proof, or local deployment with production approval.

This leads to a practical developer rule:

> A workload may propose an action. A bounded policy and authority path must authorize it. An evidence record must support the claim made about it.

The intended result is not zero risk. It is a system whose privileges, state transitions, and release claims are easier to constrain, test, audit, and revoke.

## Evidence and release engineering

FAISAL treats evidence as an input to authority, not as decorative project status. The public tree includes build, validation, and release-engineering tooling, but the readiness model remains fail-closed when external proof is absent.

| Evidence class | What it can support | What it cannot replace |
|---|---|---|
| Local build and regression results | Candidate integrity and repeatable local validation | Independent builder reproduction or production approval |
| QEMU and bounded test fixtures | Controlled functional and recovery evidence | Physical hardware qualification |
| Contract validation | Policy, receipt, replay, and denial-path behavior | A real operator signing ceremony |
| Hardware qualification matrix | Defined requirements and evidence schema | Observed GPU/NPU/IOMMU/RDMA/CXL/NVMe/TPM capability |
| Security-review contract | Review scope and remediation structure | An independent external assessment |
| Multihost qualification contract | Required workload, fault, recovery, and migration evidence | A live distributed deployment |

## Current limits

The following items remain external requirements before a production release can be claimed:

- Independent reproducible-builder qualification.
- Real operator signing ceremony with the required authority and witnesses.
- Physical hardware qualification across the required platform matrix.
- Independent external security review, remediation, and retest.
- Live multihost qualification under realistic distributed workloads.
- LTS requalification of the Linux 7.2 forward-port candidate.

These are deliberate blockers, not missing labels. They prevent local simulation or self-assertion from becoming a production claim.

## Repository guide

| Path | Use it for |
|---|---|
| [`AGI-KERNEL-ARCHITECTURE.md`](./AGI-KERNEL-ARCHITECTURE.md) | High-level system architecture and boundary model. |
| [`AGI-KERNEL-READINESS-GATE.md`](./AGI-KERNEL-READINESS-GATE.md) | Fail-closed release conditions and readiness posture. |
| [`FAISAL-PROGRAM-STATE.json`](./FAISAL-PROGRAM-STATE.json) | Machine-readable project state, milestone dependencies, and non-fabrication rules. |
| [`tools/`](./tools) | Build, validation, evidence, qualification, and control-plane tooling. |
| [`COPYING`](./COPYING) and [`LICENSES/`](./LICENSES) | Linux licensing materials and file-level license references. |

## Licensing

FAISAL follows the Linux kernel licensing model. `COPYING` declares `SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note`; the text states GNU General Public License version 2 only with the explicit Linux syscall exception. Individual source files carry their applicable SPDX identifiers. Review file-level licensing before redistributing, modifying, or combining components.

## Contributing

Contributions are most valuable when they improve correctness, reproducibility, security review, explicit authority boundaries, qualification evidence, compatibility, or developer tooling. Please preserve the project’s core constraint:

> **Model output may inform a decision; it never authorizes one.**

## References

[1] [FAISAL public source repository](https://github.com/FaisalKernel/Faisal)

[2] [FAISAL architecture document](https://github.com/FaisalKernel/Faisal/blob/main/AGI-KERNEL-ARCHITECTURE.md)

[3] [FAISAL readiness gate](https://github.com/FaisalKernel/Faisal/blob/main/AGI-KERNEL-READINESS-GATE.md)

[4] [FAISAL program state](https://github.com/FaisalKernel/Faisal/blob/main/FAISAL-PROGRAM-STATE.json)

[5] [FAISAL `COPYING` licensing notice](https://github.com/FaisalKernel/Faisal/blob/main/COPYING)
