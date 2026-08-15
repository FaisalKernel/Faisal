# FAISAL M74 Trusted Model/Runtime Orchestration Design

## Scope

M74 implements a bounded userspace orchestration and policy-supervisor service. It admits a model/runtime workload only when a deterministic policy fixture receives independent supervisor and operator approvals, a model identity/digest is present, and requested CPU/memory limits fit the configured policy. The model adapter remains outside the kernel. This milestone does not implement a foundation model, inference engine, browser, tool executor, or semantic planner.

## Trust boundaries

The model/runtime is an untrusted producer of proposed outputs. Its output is digested, recorded, and classified as a proposal. It cannot directly call a privileged kernel ioctl through the orchestration API, create capabilities, open a browser session, mutate world-state, or authorize a tool. The supervisor policy and operator approval are separate inputs. The FAISAL kernel enforces the session identity, lifecycle, budget, gate, checkpoint, and capability boundaries; the service applies higher-level admission policy.

| Input or actor | Trust level | Permitted effect |
|---|---|---|
| Model output | Untrusted | Record a digest and proposed action metadata; no authorization |
| Runtime adapter | Constrained userspace component | Submit a workload result through the supervisor |
| Supervisor policy fixture | Trusted test policy | Approve or deny bounded admission according to explicit limits |
| Operator approval | Independent approval input | Required for the test admission path; does not bypass kernel checks |
| FAISAL kernel session | Enforcing authority | Enforce identity, lifecycle, budgets, gate, checkpoint, recovery, and capabilities |
| Production deployment controller | Out of M74 scope | Must require an independent trusted supervisor and operator approvals |

## Admission contract

An admission request contains a bounded model identifier, model artifact digest, requested CPU time, requested memory pages, workload class, proposed action mask, supervisor approval, operator approval, and approval nonces. The policy fixture rejects empty or oversized identifiers, zero or malformed digests, resource requests above policy limits, missing or duplicate approval nonces, and unsupported workload classes. The proposed action mask is retained for audit only and is never passed to a capability-grant operation.

A successful admission configures the FAISAL session CPU and memory budgets, closes the execution gate, and creates a checkpoint record. The checkpoint state digest is derived from the admitted model identity, request fields, policy generation, and input provenance. The service then creates a checkpoint manifest, verifies the checkpoint against the kernel response, and records the admission as checkpoint-protected. No successful admission is reported until the independent policy gate and kernel verification both pass.

## Output and provenance contract

A result contains the admitted run ID, output digest, model digest, parent checkpoint sequence, and proposed action metadata. The service records the result through M71 persistent memory with the model digest and checkpoint sequence as provenance fields. A result may be marked `PROPOSED`, `REJECTED`, or `VERIFIED_BY_POLICY`; even the last state means only that the deterministic policy fixture accepted the result format and provenance, not that the model output is true or authorized. M74 has no operation that converts a model proposal into a filesystem, network, browser, device, process, or capability grant.

## Checkpoint and rollback

The kernel checkpoint lifecycle is explicit:

```text
ADMIT → SET CPU/MEMORY BUDGET → CLOSE GATE → CHECKPOINT
      → CHECKPOINT MANIFEST → VERIFY CHECKPOINT
      → EXPORT HANDOFF

FAILURE → MARK_CRASH → RESTORE_BEGIN → IMPORT HANDOFF
        → VERIFY CHECKPOINT → RECOVERY_CONTINUE
```

The service keeps the kernel checkpoint ID, checkpoint sequence, parent sequence, state digest, manifest digest, and handoff fields. It does not claim that kernel checkpointing snapshots arbitrary model device state; accelerator resources remain provider- and manifest-gated. A rollback restores the verified control-plane state and userspace handoff contract. The model/runtime must separately restore its own durable state and revalidate it.

## Resource and approval policy

M74 uses measured resource snapshots for observation and kernel budgets for enforcement. Snapshot fields marked unavailable or unsupported are not treated as zero capacity or as proof of hardware availability. The policy fixture rejects a request when the configured budget exceeds its explicit ceiling; it does not infer capacity from provider metadata. Production policy changes remain outside the deterministic fixture and require an independent trusted supervisor plus operator approval.

## Recovery and failure behavior

If admission fails, no model result is committed as verified and the service reports the exact denial class. If checkpoint creation, manifest creation, or verification fails, the run remains denied and the gate is not opened. If a run is marked crashed, restoration requires matching checkpoint sequence, parent sequence, state digest, manifest digest, lineage, and kernel verification state. A digest mismatch is a hard failure. The service never fabricates a restored model state.

## Explicit non-claims

M74 does not claim model intelligence, reliable reasoning, semantic truth, self-awareness, consciousness, autonomous tool use, browser control, model training, safe real-world action, or production deployment. A policy-approved result is not a true result. A checkpoint is not a complete model-state snapshot unless the separately validated runtime and manifest prove that property. Model output never equals kernel authorization.
