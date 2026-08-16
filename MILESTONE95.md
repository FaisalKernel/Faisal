# FAISAL M95 — Durable Objective and Task Execution

## Summary

M95 implements the first durable objective-execution contract selected from the complete pasted specification. It adds a bounded userspace service, `tools/faisal-task/`, that persists task snapshots, reconstructs state after restart, prevents duplicate submissions, enforces dependency completion, tracks leases and heartbeats, schedules retryable failures with bounded backoff, dead-letters exhausted work, enforces deadline and budget stop conditions, supports explicit cancellation, and fails closed on journal corruption.

The service is intentionally not a model runtime, planner, browser, database cluster, or kernel-resident semantic engine. It binds to the real FAISAL kernel control plane in QEMU by verifying ABI 38, creating a lifecycle session, attaching the current task, registering a planner light agent, and selecting that agent. Kernel capabilities, M94 intent leases, cancellation, accounting, provenance, and checkpoint references remain the enforcement boundary.

## Why this increment was selected

The complete pasted specification contains broad requirements for mission mode, continuous operation, planning, recovery, verification, learning, value measurement, and enterprise-scale execution. Existing FAISAL milestones provide many individual primitives, but repository inspection found no first-class durable task queue with idempotency, worker lease generation, heartbeat, retry policy, dead-letter handling, dependency gating, or explicit stop conditions. M95 fills that central execution-state gap before adding broader mission scheduling or provider ownership recovery.

## Implemented artifacts

| Artifact | Purpose |
|---|---|
| `tools/faisal-task/faisal_task_service.h` | Bounded task record, state, failure, stop, and service API. |
| `tools/faisal-task/faisal_task_service.c` | Journal, replay, state transitions, leases, retries, budgets, deadlines, cancellation, and kernel handshake. |
| `tools/testing/selftests/agi_durable_task_test.c` | Functional, recovery, concurrency, corruption, idempotency, dependency, retry, and stop-condition test. |
| `tools/faisal-build/run_durable_task_qemu.sh` | Static initramfs and kernel-integrated QEMU validation harness. |
| `M95-DURABLE-TASK-DESIGN.md` | Design and boundary record. |
| `M95-SECURITY-REVIEW.md` | Threat model and security assessment. |
| `M95-BENCHMARKS.md` | Measured validation timings and interpretation limits. |
| `M95-RESEARCH-NOTES.md` | Authoritative Linux workqueue and pidfd research record. |

## Final verification

| Gate | Result |
|---|---|
| Strict static build | Passed |
| Host functional selftest | Passed |
| AddressSanitizer + UndefinedBehaviorSanitizer with leak detection | Passed |
| ThreadSanitizer | Passed without race diagnostics |
| QEMU ABI 38 kernel binding | Passed |
| QEMU durable-task integration | Passed |
| Three clean QEMU smokes | Passed 3/3; 6,184–6,243 ms |
| Complete existing FAISAL audit | Passed 23/23 harnesses |
| M90 signed-provider regression | Passed |
| M91 provider-gated hardware-attestation regression | Passed |
| Security pattern scan and diff hygiene | Passed |

The selftest emitted all final markers, including `M95_IDEMPOTENT_SUBMIT_OK`, `M95_DEPENDENCY_GATE_OK`, `M95_LEASE_HEARTBEAT_COMPLETE_OK`, `M95_RETRY_BACKOFF_REPLAN_OK`, `M95_RESTART_RECOVERY_OK`, `M95_POLICY_CANCEL_STOP_OK`, `M95_DEADLINE_STOP_OK`, `M95_BUDGET_STOP_OK`, `M95_RETRY_EXHAUSTION_DEAD_LETTER_OK`, `M95_CONCURRENT_QUERY_OK`, `M95_REPLAY_STATE_OK`, `M95_CORRUPTION_FAIL_CLOSED_OK`, and `M95_SELFTEST_EXIT=0`.

## Acceptance boundary and non-claims

M95 proves a bounded durable task state machine and a real kernel-session integration path. It does not prove distributed consensus, exactly-once side effects, arbitrary process recovery, multi-node replication, complete goal hierarchies, universal policy interception, hardware-backed identity, enterprise tenancy, general AGI, consciousness, model retraining, or any fixed productivity multiplier. Task text remains untrusted data, and model output is never authorization.

## Next dependency

The next dependency is **M96: supervisor-mediated provider ownership, stale-service reclamation, and explicit crash recovery**, using stable process-lifetime supervision and the existing M93/M94 provider and intent-lease foundations. M96 should be implemented only after preserving the M95 journal/task ownership and replay contracts.
