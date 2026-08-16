# FAISAL M101 Security Review — Deadline-aware AGI scheduling urgency

## Security objective

M101 makes an existing FAISAL scheduling hint more useful for latency-sensitive agent work without converting model output into authority. The change is deliberately narrow: it derives a coarse utilization hint from an absolute monotonic deadline and existing latency-sensitive metadata, then calls Linux’s existing util-clamp scheduler interface.

## Threat model

The untrusted caller may be a compromised model, a prompt-injected service, a buggy agent, or a malicious userspace process that already possesses a valid FAISAL lifecycle session. It may submit extreme priorities, deadlines in the past or distant future, contradictory utilization bounds, repeated updates, or stale lineage information. The kernel must prevent the hint from becoming unrestricted privilege or an execution guarantee.

| Threat | Control | Result |
|---|---|---|
| Unauthorised process submits a hint | Existing session identity, revocation, and `faisal_task_get_lineage(current)` checks precede scheduler mutation | Denied before mutation |
| Malformed utilization values | Existing bounds require `util_min <= util_max <= SCHED_CAPACITY_SCALE` and bounded `unblock_credit` | Rejected with `-EINVAL` |
| Deadline integer abuse | Monotonic subtraction is performed only after checking `deadline_ns <= now`; bounded coarse thresholds use unsigned constants | No underflow path in the urgency calculation |
| Hard real-time or CPU-bandwidth assumption | Linux util-clamp is used as a scheduler/frequency hint; no admission or bandwidth guarantee is added | Explicitly not a hard deadline guarantee |
| Configuration without util-clamp | Helper is compiled only under `CONFIG_UCLAMP_TASK`; existing `-EOPNOTSUPP` fallback remains | Safe capability discovery |
| Model output becoming authority | The model cannot bypass lifecycle capability, lineage, revocation, cgroup, affinity, or scheduler controls | Authorization boundary preserved |
| ABI drift | Only a UAPI comment clarifies `deadline_ns`; no struct size, ioctl number, or ABI version changes | ABI 38 preserved |
| Kernel fault or regression | Strict build, optimized-kernel QEMU selftest, unmodified-kernel matched control, graph telemetry regression, sanitizer builds, GCC analyzer, and shell checks | Evidence recorded; not formal proof |

## Review findings

The implementation is small, stateless, and bounded. It has no dynamic allocation, no user pointer dereference beyond the existing copied structure, no new lock, no new persistent state, no network path, and no capability creation. The helper uses `ktime_get_ns()` and does not trust a user-provided current time. The urgency bands are intentionally coarse to prevent pretending that a model can provide precise scheduler truth.

The change does not prevent a valid agent from requesting a high utilization hint. That is an intended policy surface and must be controlled by the higher-level authority and resource-budget layers already present in FAISAL. The kernel only enforces the existing session/lineage boundary and scheduler input limits.

## Residual risks

Util-clamp is not a real-time scheduler and cannot guarantee that a task runs before its deadline. A high minimum utilization hint may increase frequency or contention and can affect energy use. The current implementation does not account for runnable competing work, accelerator queue state, thermal headroom, or deadline admission. The QEMU benchmark does not establish physical performance, energy impact, fairness, or security against kernel exploits.

## Security conclusion

M101 is acceptable as a bounded experimental kernel enhancement subject to the existing FAISAL trusted-supervisor and independent operator approval model. It must not be described as hard real-time scheduling, universal kernel superiority, autonomous authority, or production-ready self-optimization until hardware measurements, stress, fairness, power, and longer-duration regression evidence exist.
