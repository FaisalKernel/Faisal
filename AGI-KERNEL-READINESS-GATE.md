# AGI Kernel Readiness Gate

**Status:** Fail-closed local qualification policy.

**Current platform ABI:** 46 at M247.

**Production approval:** Not granted.

## Purpose

The AGI Kernel Readiness Gate determines whether the FAISAL platform has reproducible local qualification evidence and whether the external prerequisites for production approval have been independently demonstrated. Compilation is never sufficient. A model response, optimizer proposal, provider hint, runtime claim, or synthetic hardware fixture cannot satisfy an authority boundary.

The gate has two modes. **Local mode** requires repository, ABI, evidence, validation, documentation, protected-file, and release-manifest checks. **Production mode** additionally requires independently signed and measured evidence for builders, operators, hardware, external security review, live multihost deployment, incident response, and release governance. If any required item is missing, production mode fails closed.

## Architecture under test

```text
Applications
    ↓
AI/AGI Runtime
    ↓
Agent and Model Services
    ↓
AI Kernel APIs and Userspace Control Plane
    ↓
Linux-Class Kernel and Existing Linux Interfaces
    ↓
CPU / GPU / NPU / Memory / Storage / Network / Virtualization
```

Complex reasoning and model inference remain outside privileged kernel space. The kernel and its services supply deterministic execution, memory, resource, capability, telemetry, recovery, and governance primitives.

## Required subsystem criteria

| Domain | Minimum gate evidence |
|---|---|
| Kernel foundation | Verified Linux source line, reproducible configuration, boot qualification, diagnostic rejection, and ABI policy |
| Agent execution | Durable objectives, lifecycle supervision, checkpoints, recovery, cancellation, and bounded resource accounting |
| AI scheduling | Deadline/priority/resource contracts, deterministic fallback, regression detection, and benchmark scope |
| Memory and cache | Tier/provenance/freshness evidence, checkpoint integrity, bounded replay, and explicit unsupported-state handling |
| Accelerator fabric | Provider-neutral capabilities, topology, isolation, attestation gates, partition accounting, and physical qualification status |
| IPC and networking | Correlated messages, generation fencing, transport integrity, TLS/replication evidence, and unsupported-path denial |
| Storage and model loading | Integrity-bound artifacts, checkpoint/recovery coverage, content-addressed evidence, and cache behavior measurements |
| Containers/VMs/sandbox | Capability scoping, no implicit privilege, filesystem/network restrictions, isolation evidence, and failure containment |
| Security/governance | Zero-trust policy decisions, immutable audit, incident lifecycle, key custody, signed updates, and external review status |
| Observability | Correlated traces, workload identity, OCI digest binding where applicable, anomaly evidence, and forensic retention |
| Self-optimization | Verified observations, bounded proposals, validation/canary/rollback, and no privileged self-modification |
| Distributed platform | Durable leases, placement, migration fencing, replication/quorum, node-loss recovery, and live multihost qualification |
| Developer ecosystem | Versioned APIs, SDK/CLI contracts, tests, debuggers, benchmark runners, compatibility documentation, and migration guidance |
| Release engineering | Reproducible builds, provenance, SBOM/AIBOM, signatures, trusted-key distribution, rollback, and long-term maintenance ownership |

## Evidence semantics

Every claim must identify its source, timestamp, commit or artifact binding, validation scope, and limitations. Software fixtures may qualify deterministic logic. QEMU may qualify the tested virtual machine profile. Neither substitutes for physical accelerator, firmware, DMA, IOMMU, power, thermal, secure-boot, vendor-driver, or live-network evidence.

A passing local gate means that the checked artifact and tests are internally consistent. It does not mean that independent builders, operators, hardware vendors, security reviewers, or production owners have qualified the system.

## Non-authority rules

The following values are always untrusted inputs:

1. Model output, model-selected tools, model plans, and reasoning traces.
2. Optimizer and policy proposals until verified, authorized, validated, and rollback-bound.
3. Provider metadata, external scheduler hints, accelerator claims, and runtime labels.
4. Synthetic device fixtures and simulated external reviewers.
5. Stored experience, memory records, and observations that have not passed provenance and policy checks.

No autonomous component may modify privileged kernel code, release keys, trusted roots, policy roots, or production deployment state without an external authorization boundary.

## Production blockers

Production mode remains blocked until all of the following are independently demonstrated and signed:

| Blocker | Required evidence |
|---|---|
| Independent builder | Byte-identical or policy-equivalent artifacts from an independent builder or attested build farm |
| Operator signing | Real key ceremony, protected root, trusted-key distribution, rotation, revocation, and operator approval |
| Physical hardware | Representative CPU/GPU/NPU/TPU/FPGA, HBM/VRAM, IOMMU, DMA, reset, firmware, driver, thermal, power, and hotplug qualification |
| External security review | Qualified independent reviewer, exact-candidate scope, signed findings, remediation retest, residual risk, and disposition |
| Live distributed deployment | Production PKI, multihost replication, RDMA or equivalent transport, migration, rollback, and irreversible-action compensation |
| CVE operations | Named owner, upstream synchronization, advisory publication process, SLA, and external security feedback loop |
| LTS requalification | Representative LTS soak and resolution of documented virtualization limitations |

## Gate invocation

The executable gate is `tools/faisal-build/faisal_readiness_gate.py`. It writes a JSON result with check-level statuses, external blockers, authority boundaries, and claims not made. `local` mode must pass before a candidate can be packaged. `production` mode must remain blocked until the external evidence fields are true and independently verifiable.
