# FAISAL M98 — Mission Autonomy Control Loop Benchmarks

**Status:** Validation-backed benchmark record

**Date:** 2026-08-16

## Measurement boundary

M98 was measured as a validation envelope, not as a claim that FAISAL is faster than Linux or existing agent frameworks. The primary measurement is the wall-clock time for a clean QEMU boot, real ABI-38 intent-lease acquisition, mission creation, observation, unauthorized-proposal rejection, authorized branch preparation, evidence-complete commit, continuity drift detection, restart recovery escalation, deadline stop, concurrent queries, and journal corruption rejection.

| Run | Result | Wall time |
|---|---:|---:|
| Final smoke 1 | Pass | 6,296 ms |
| Final smoke 2 | Pass | 6,297 ms |
| Final smoke 3 | Pass | 6,210 ms |
| **Minimum / maximum / mean** | **3/3 pass** | **6,210 / 6,297 / 6,267.67 ms** |

The timing includes QEMU and kernel boot overhead, so it is not an isolated mission-state-machine latency measurement. It is retained as a reproducibility envelope for the current virtualized test environment.

## Validation matrix

| Test | Result | Evidence |
|---|---:|---|
| Strict host build | Pass | `m98-compile-final2.log` |
| Host mission selftest | Pass | `m98-host-final2.log` |
| ASan/UBSan | Pass, exit 0 | `m98-asan-ubsan-final.log` |
| TSan | Pass, exit 0 | `m98-tsan-final.log` |
| Kernel-integrated QEMU | Pass, exit 0 | `m98-qemu-final2.log` |
| Clean QEMU smokes | 3/3 pass | `m98-smokes-final.log` and `m98-smoke-final-*.log` |
| M95 durable-task regression | Pass | `m98-M95_DURABLE_QEMU.log` |
| M96 causal-authority regression | Pass | `m98-M96_CAUSAL_QEMU.log` |
| M90 key-provider regression | Pass | `m98-M90_KEY_PROVIDER_QEMU.log` |
| M91 provider-gate regression | Pass | `m98-M91_PROVIDER_GATE_QEMU.log` |
| Full FAISAL audit | 23/23 pass | `m98-full-audit.log` |
| Security pattern scan | Pass | `m98-security-scan.log` |

## Bounded baseline and superiority work

A future benchmark comparison should run two implementations over the same scripted mission trace. The baseline should persist only a task checkpoint and restart from the last record without M96 branch evidence and M97 state-vector validation. The M98 path should require the causal branch, exact continuity vector, per-invocation authority, and deterministic stop/escalation states.

Required metrics are recovery decisions after stale state, duplicate-action prevention when execution was in flight, false continuation rate after world/resource drift, time to safe stop after budget/deadline breach, escalation rate on unverifiable results, journal bytes per mission step, restart replay latency, concurrent query throughput, and CPU/memory overhead. These measurements were not completed in this milestone and therefore no superiority claim is made.

## Non-claims

The measurements do not establish higher agent task success, lower tool latency, lower energy use, larger scalability, better model reasoning, exactly-once external side effects, distributed consensus, production readiness, or a productivity multiplier. They also do not establish that the supplied state digests are truthful; they only establish that mismatches are detected by the contract.

## References

[1]: https://arxiv.org/html/2602.16666v1 — Rabanser et al., “Towards a Science of AI Agent Reliability,” 2026.

[2]: https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative — NIST, “AI Agent Standards Initiative,” updated 2026.
