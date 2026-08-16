# FAISAL M85 — Self-Healing Security Review

## Scope

This review covers the userspace self-healing supervisor, its integration with M78 deployment and M71 checkpoint services, the M85 selftest, and the QEMU harness. It does not certify arbitrary autonomous code generation, the entire FAISAL kernel, or production deployment.

## Threat model

The supervisor assumes that model output, external observations, dependency metadata, repair descriptions, and proposed code can be wrong or malicious. A compromised model must not be able to authorize its own repair. A hostile signal must not trigger unrestricted code execution. A failed service must not cause an infinite restart loop or erase the last verified state.

## Controls

| Threat | Control |
|---|---|
| Model proposes privileged repair | Model output is not an approval or capability; candidate needs independent trusted approvals |
| Forged candidate | Recomputed SHA-256 candidate digest and M78 integrity contract |
| Unauthorized repair | Supervisor/operator/integrity/canary approval bits and policy checks |
| Bad repair | Checkpoint before activation, canary health gate, rollback on failure |
| Corrupted checkpoint | Existing M71 digest verification and handoff validation |
| Journal digest mutation during rollback | Post-checkpoint signals/audit remain in bounded supervisor memory until recovery verification |
| Security compromise | Security signals quarantine; they do not trigger autonomous repair |
| Restart loop | Three-attempt cap followed by quarantine |
| Unknown input | Strict signal kind/severity/sequence validation and bounded arrays |
| Audit loss | Explicit in-memory transition records plus durable pre-checkpoint event records where safe |
| Kernel modification abuse | M85 does not compile, load, sign, or patch kernel code |

## Recovery safety

Automatic rollback is permitted only for known reversible classes and an existing verified checkpoint. Repair activation is permitted only for dependency-class failures and a candidate that passes the M78 candidate contract. Canary failure causes rollback. Rollback failure causes `FAILED`, not silent continuation. Security and unknown failures cause `QUARANTINED`.

## Static review

The implementation uses fixed-size records, bounded strings, `snprintf`, explicit error returns, and existing M78/M71 APIs. It contains no shell execution, process spawning, dynamic code loading, kernel patching, or direct model invocation. The selftest covers automatic rollback, approved repair canary success, canary-failure rollback, security quarantine, retry-limit quarantine, audit retention, and QEMU boot.

## Remaining gaps

M85 does not claim KASAN, KCSAN, UBSAN, lockdep, syzkaller, randomized signal fuzzing, distributed transactional rollback, signed repair bundle verification, hardware-backed attestation, or multi-tenant hostile deployment. The repair candidate is validated against the existing userspace supervisor contract, but the candidate production pipeline itself remains outside this milestone.
