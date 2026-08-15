# FAISAL M74 — Trusted Model/Runtime Orchestration

**Status:** Implemented and validated in two-vCPU QEMU.
**Kernel base:** Linux `v7.2-rc7`.
**FAISAL ABI:** 37.
**Scope:** Userspace model/runtime admission and policy supervision integrated with FAISAL CPU/memory budgets, execution gates, checkpoint manifests, checkpoint verification, handoff, recovery, and M71 durable provenance.

## Implementation

M74 adds `tools/faisal-orchestrator/faisal_orchestrator_service.c` and its header. The service is a deterministic policy fixture and kernel integration layer, not a model runtime. It admits a bounded model request only when model identity and digest are present, the workload class is supported, CPU and memory requests fit explicit policy ceilings, and distinct supervisor and operator approvals are present.

An admitted request sets kernel CPU and memory budgets, closes the FAISAL execution gate, creates a checkpoint, publishes a checkpoint manifest, verifies the checkpoint digest and sequence, and exports a validated handoff. The service stores the admission through M71 with checkpoint sequence provenance. The policy retains any proposed action mask for audit but never passes it to a capability grant or privileged action interface.

Model output is digested and retained as an untrusted proposal. The selftest demonstrates that output recording can preserve a nonzero proposed action mask while the service reports `M74_MODEL_OUTPUT_NOT_AUTHORITY_OK`. A format-accepted proposal is not treated as true, safe, or authorized. The rollback path marks the checkpoint crashed, begins restore with matching checkpoint and manifest digests, imports the validated handoff, and continues only after the FAISAL recovery state reaches `CONTINUED`.

## Validation

The static service/selftest build passed with `-O2 -Wall -Wextra -Werror -Wno-cpp` and static OpenSSL EVP linkage. The M74 QEMU harness passed with a dynamic lifecycle-device node and the following markers.

```text
FAISAL_M74_BOOT_OK
M74_POLICY_FUZZ_REJECT_OK iterations=128
M74_POLICY_DENIALS_OK
M74_RESOURCE_ADMISSION_OK run=1 cpu_ns=100000000 memory_pages=1024
M74_MODEL_OUTPUT_NOT_AUTHORITY_OK action_mask=0x10
M74_CHECKPOINT_ROLLBACK_OK checkpoint=74001 recovery=3
M74_MODEL_IDENTITY_BOUNDARY_OK
M74_SELFTEST_EXIT=0
FAISAL_M74_TEST_RC=0
```

Five repeated M74 QEMU smoke runs passed. Wall time ranged from 5.0214 to 5.1499 seconds, including kernel boot, initramfs construction, policy fixture execution, checkpoint/rollback, and forced shutdown. The full M64 and M66–M73 regression suite passed, for ten of ten harnesses in the M74 regression run. No M74 failure marker, kernel panic, `BUG`, or `Oops` was found in the captured logs.

## Acceptance gates

| Gate | Result | Evidence |
|---|---|---|
| Model output is not authority | Pass | Nonzero proposed action mask retained without capability-grant path; explicit marker |
| Resource admission | Pass | CPU and memory ceilings enforced and kernel budgets set |
| Independent policy gate | Pass | Missing supervisor/operator approval, duplicate nonces, unsupported workload, and oversize budget denied |
| Checkpoint | Pass | Checkpoint, manifest, verification, and export handoff completed |
| Rollback | Pass | Crash mark, restore begin, handoff import, and recovery continue completed |
| Policy fuzz boundary | Pass | 128 reserved-field mutations rejected before admission |
| Build and boot | Pass | Strict static build and QEMU boot markers |
| Regression | Pass | M64 and M66–M73 harnesses, plus M74 |

## Explicit non-claims

M74 does **not** implement or claim a foundation model, inference quality, general intelligence, semantic truth, consciousness, self-awareness, browser control, tool execution, model training, or safe real-world action. A policy-approved model result is not necessarily true. A checkpoint is not claimed to contain arbitrary accelerator or model state without a separately validated manifest and runtime. Model output, memory records, confidence, checkpoint state, and policy approval never equal kernel authorization. Production deployment requires an independent trusted supervisor and operator approvals.

## Evidence

The design contract is `M74-MODEL-ORCHESTRATION-DESIGN.md`; the security review is `M74-SECURITY-REVIEW.md`; benchmark limits are in `M74-BENCHMARKS.md`; machine-readable evidence is `tools/faisal-build/evidence/m74-model-orchestration-validation.json`; and raw M74, regression, benchmark, and build logs are under `tools/faisal-build/evidence/`.
