# FAISAL M72 Measurements

M72 measures the control flow needed to retain and operationalize an experience: kernel recording, M71 durable-memory insertion, evaluation gating, artifact publication, retrieval, reuse recording, stale-capability rejection, and correction/re-evaluation.

Three repeated two-vCPU QEMU runs passed. These are repeatability smoke observations, not a performance comparison.

| Measurement | Observation | Interpretation |
|---|---|---|
| Static service/selftest build | Passed with strict warnings | Userspace integration compiles cleanly. |
| QEMU repeated runs | 3 of 3 passed | Pipeline behavior is repeatable in the fixture. |
| Query 1 | Kernel experience sequence and M71 memory record created | Retention is demonstrated. |
| Query 2 | Exact reusable artifact retrieved | Same-service-session reuse is demonstrated. |
| Correction | New experience/artifact replaces corrected index state | Re-evaluation is demonstrated. |
| Stale capability | Kernel returned denial | Artifact metadata access is capability-scoped. |

A meaningful benchmark requires a real workload and baseline comparison across evaluator cost, M71 journal `fdatasync()` cost, kernel ioctl cost, artifact retrieval latency, correction latency, index size, concurrent agents, false reuse rate, false rejection rate, and end-to-end task success. M72 does not measure model quality, generalization, learning speed, or inference improvement. No such claim is made.
