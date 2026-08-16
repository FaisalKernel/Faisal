# FAISAL M97 — Continuity Capsule Security Review

**Status:** Reviewed against the implemented service, selftest, and QEMU harness

**Date:** 2026-08-16

**Author:** Manus AI

## Security objective

M97 prevents a durable task or checkpoint from being treated as resumable merely because it exists. A Continuity Capsule is resumable only when its committed causal branch, task objective generation, working-state digest, world-state digest, and resource-state digest still match. The capsule check is deliberately observational and never grants authority for a new action.

> A resume decision is not an authorization decision. Any new external side effect requires a fresh M96/M94 authority path.

## Threat model and controls

| Threat | M97 control | Evidence |
|---|---|---|
| Working memory or checkpoint changed after commit | Exact working-state digest comparison | `M97_WORKING_STATE_DRIFT_REJECTED_OK` |
| World observation became stale | Exact world-state digest comparison | `M97_WORLD_STATE_DRIFT_REJECTED_OK` |
| Resource or thermal admission changed | Exact resource-state digest comparison | `M97_RESOURCE_STATE_DRIFT_REJECTED_OK` |
| Task objective generation advanced | Current task sequence must equal capsule generation | Source-level invariant and exact-resume test |
| Committed branch was altered or replayed from another lineage | Current canonical branch digest must equal capsule branch digest | Source-level invariant and replay test |
| Branch or capsule invalidated | Resume returns `FTS_ERR_REVOKED` | `M97_CONTINUITY_INVALIDATION_REVOKED_OK` |
| Capsule journal is truncated or modified | Header, sequence, bounds, state, nonzero digest, and canonical SHA-256 validation; startup fails closed | `M97_CONTINUITY_CORRUPTION_FAIL_CLOSED_OK` |
| Malicious model presents a stale resume as safe | Model output is never read as authority; only supplied trusted-service digests and M96 branch state are checked | Security scan and design boundary |
| Resource exhaustion via capsules | Maximum 64 capsules; fixed-size records; bounded journal replay | Source review |
| Concurrent capsule mutation races | Service lock serializes seal, check, invalidate, query, append, and replay mutation | TSan pass |

## Trust boundaries

M97 trusts the service components that produce the three state digests only to the extent that their own security and provenance policies have been validated. M97 does not inspect or interpret their semantic content. A digest proves equality of an input representation, not truthfulness of the represented world, memory, or resource state.

The M94 kernel intent lease remains the authority boundary for side effects. The M97 capsule journal does not replace Linux capabilities, LSM policy, namespaces, seccomp, cgroups, pidfds, HMM, or checkpoint/restore systems. It composes with them by making the cross-layer resume precondition explicit.

## Fail-closed behavior

M97 rejects service startup when the continuity journal contains malformed headers, invalid record sizes, non-monotonic sequence values, unknown states, missing identity fields, zero state digests, or a digest mismatch. It rejects sealing unless the referenced M96 branch is committed and the three supplied state digests are nonzero. It rejects resume when any state vector member differs, the task generation changed, the branch is not committed, the branch digest changed, or the capsule was invalidated.

The implementation does not attempt automatic repair of a corrupted continuity journal. This is intentional: silently reconstructing a possibly stale state would defeat the purpose of a continuity contract. Recovery must be supervised and evidence-producing.

## Memory and concurrency safety

Continuity records use fixed-width fields and fixed-size arrays. The replay path validates sizes before reading records. The final M97 selftest passed with AddressSanitizer and UndefinedBehaviorSanitizer, and ThreadSanitizer reported no race. Strict compilation used `-Wall -Wextra -Werror`.

These tests cover the exercised paths and do not constitute a proof of memory safety. Fuzzing malformed continuity records and randomized multi-threaded state-vector mutation remain future hardening work.

## Security scan

The M97 implementation, selftest, harness, research, and design files were scanned using fixed-string matching for `system(`, `popen(`, `execve(`, `setuid(`, `ptrace(`, `invokeLLM`, `model_output`, `livepatch`, and `CAP_SYS_ADMIN`. All specified patterns were clear. This is a screening measure, not a substitute for kernel security review or formal analysis.

## Residual risks

The strongest residual risk is producer integrity: a compromised service could report a false but internally consistent digest. M97 therefore cannot establish world truth, memory confidentiality, thermal safety, or external side-effect correctness by itself. It also does not create a checkpoint or move memory; it requires trusted services to supply the state identities. Capsules are local append-only records and do not provide distributed consensus or rollback of irreversible remote operations.

## Conclusion

The implemented M97 contract is security-useful because it refuses to collapse “durable” into “safe to resume.” It adds explicit stale-state and invalidation rejection while preserving the kernel authority boundary and failing closed on journal corruption. The implementation is suitable for a bounded FAISAL milestone, with producer integrity, fuzzing, and external-supervisor integration remaining explicit future work.

## References

[1]: https://docs.kernel.org/mm/hmm.html — Linux kernel documentation, “Heterogeneous Memory Management.”

[2]: https://www.usenix.org/conference/osdi24/presentation/zhong-yuhong — Zhong et al., “Managing Memory Tiers with CXL in Virtualized Environments,” OSDI 2024.
