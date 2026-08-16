# M81 Security Review — Concurrent Lifecycle and IPC Stress

## Scope

M81 reviews the new userspace stress service, selftest, QEMU harness, and the existing ABI 37 lifecycle/IPC paths exercised by the workload. The test is not a new authorization mechanism and does not change kernel security policy.

## Threats and Controls

| Threat | Exercised control | Result |
|---|---|---|
| Malformed userspace structure | Invalid size submitted to `AGI_LC_IPC_SEND` | 512/512 requests rejected with `EINVAL` |
| Forged sender capability | Source capability bit mutation | 8/8 workers receive denial |
| Forged channel capability | Consumer channel capability bit mutation | 8/8 workers receive denial |
| Unauthorized cancellation | Cancellation uses the source agent and source capability | 48/48 intended cancellations return `-ECANCELED` |
| Cross-session interference | Eight separate lifecycle sessions and descriptors | No cross-worker state is accepted; 8/8 workers pass |
| Queue exhaustion | Bounded queue and nonblocking sends | `EAGAIN` is observed as backpressure, not bypassed |
| Stale message handling | Message identifiers returned by the kernel are required for cancellation | No guessed message identifiers are accepted |
| Model or planner privilege escalation | No model invocation or privileged command path in M81 | Not applicable; model output is never consulted |
| Memory corruption or race | Generic KASAN, strict KCSAN, and lockdep builds | No KASAN/KCSAN/lockdep signatures in final M81 logs |

The service contains no `system`, `popen`, `execve`, `execl`, `setuid`, `ptrace`, or `CAP_SYS_ADMIN` primitive. The recorded source scan is `M81_SECURITY_SCAN=PASS`.

## Capability and Identity Boundary

The kernel requires the current task’s selected agent to match the IPC sender endpoint and requires the channel capability and endpoint capability to match the channel record. The M81 test intentionally mutates each of those handles and requires denial. The verifier child is registered only after the worker selects the planner parent, matching the kernel’s parent-agent authorization rule.

A separate session is not treated as a shared authority domain. M81 therefore does not claim cross-session channel sharing; it validates concurrent independent sessions and concurrent operations within each session’s kernel-owned channel. This limitation is important for future multi-agent design.

## Sanitizer Interpretation

The final KASAN configuration uses Generic KASAN with inline instrumentation, `PROVE_LOCKING`, `DEBUG_LOCK_ALLOC`, and `LOCKDEP`. The final KCSAN configuration uses strict KCSAN, KCSAN selftests, and the same lockdep controls. Both kernels built successfully and booted the M81 workload in QEMU. No sanitizer or lockdep report was found in the final logs.

The first KASAN run used two virtual CPUs and printed RCU starvation warnings under the cost of instrumentation. It was not treated as a clean result. A four-vCPU rerun completed without the warnings and is the recorded result. This demonstrates that the test harness retains infrastructure warnings rather than filtering them.

## Residual Risk

KCSAN is sampling-based and therefore not exhaustive. A passing run cannot establish race freedom. The QEMU environment does not represent all hardware, NUMA, accelerator, DMA, network, or production scheduling conditions. The test also does not exercise every lifecycle ioctl, every lock-order path, or arbitrary malformed byte patterns. These residual risks keep M81 bounded and do not justify production-security claims.

## Security Conclusion

M81 passes its defined security acceptance criteria in the tested configurations. The implementation preserves the rule that **model output is not kernel authority** and uses existing kernel capability and lineage checks rather than introducing an application-level bypass.
