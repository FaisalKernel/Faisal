# FAISAL M80 — Cross-Subsystem Stress and Failure-Injection Validation

## Result

FAISAL M80 validates a bounded cross-subsystem stress coordinator over the existing ABI 37 kernel and the M71–M79 userspace services. The milestone does **not** add a kernel ABI and does not claim that the AGI system is production-ready. The final implementation passed the M80 QEMU harness, five independent smoke runs, and all fifteen pre-M80 FAISAL regression harnesses.

| Validation item | Observed result |
|---|---:|
| Kernel ABI exercised | 37 |
| M80 malformed-UAPI mutations | 256 rejected; 0 accepted |
| Resource-pressure samples | 8 |
| M76 compositions | 3 completed |
| Cancellation/recovery passes | 8 |
| Deterministic rollback injections | 2 |
| Retained audit records | 5 |
| Provider-unsupported propagation | 1 |
| Pre-M80 QEMU regression harnesses | 15/15 passed |
| M80 five-run smoke tests | 5/5 passed |
| Kernel panic/Oops/BUG observed | 0 in captured QEMU logs |

## Implemented scope

The M80 coordinator executes bounded malformed-UAPI rejection, constrained resource observation, repeated M76 end-to-end composition, cancellation-path repetition, M78 canary-failure rollback, and M79 provider-neutral accelerator validation. Each scenario has a fixed iteration budget. The M80 QEMU initramfs now mounts a writable tmpfs at `/tmp` before journal-backed services execute, preventing the harness from depending on the initramfs root’s writable behavior.

The stress service does not run an unbounded fuzzer and does not corrupt kernel memory. Its malformed-input loop is deterministic and finite, and its failure injection occurs at userspace orchestration boundaries. Kernel authorization remains enforced by the FAISAL ioctl checks and service capability/approval paths; model or service output is not treated as kernel authority.

## Failure found and corrected

The first M80 QEMU attempt stopped at the composition stage with `rc=0`, `state=1`, and `completed_stages=5`. The existing M76 selftest defines `state=1` as `M76_COMPLETED` and treats reflection identifiers, IPC cancellation, deployment approval, and five completed stages as the completion contract. M80 had incorrectly added `observability_emitted != 0` as a required success condition even though M76’s validated contract does not guarantee a nonzero emitted-event count for this bounded fixture. The criterion was replaced with the M76-guaranteed reflection action and reflection authority capability identifiers. A failure diagnostic was retained so a future composition regression reports the M76 return code, state, stage count, injected failure stage, and errno.

After the correction, the harness produced the following markers:

```text
FAISAL_M80_BOOT_OK
M80_MALFORMED_UAPI_REJECT_OK cases=256
M80_RESOURCE_PRESSURE_OK samples=8
M80_COMPOSITION_OK runs=3
M80_CANCELLATION_OK passes=8
M80_ROLLBACK_FAULT_INJECTION_OK passes=2
M80_AUDIT_RETENTION_OK records=5
M80_PROVIDER_UNSUPPORTED_PROPAGATED=1
M80_SELFTEST_EXIT=0
FAISAL_M80_TEST_RC=0
```

## Verification and explicit non-claims

M80 demonstrates repeated bounded contract execution in a two-vCPU, 768 MiB QEMU environment using the recovered FAISAL kernel build. It does **not** demonstrate multi-day reliability, production scheduler fairness, complete random-fuzz coverage, race freedom, KASAN/KCSAN/UBSAN/lockdep coverage, syzkaller coverage, physical accelerator execution, GPU/NPU isolation, RDMA, HBM/VRAM availability, model quality, semantic learning, consciousness, or production readiness. Stored experience remains storage and operationalization; it is not evidence that a foundation model was retrained. Provider metadata remains distinct from hardware proof.

M80 also does not replace hardware testing or a sanitizer-enabled kernel configuration. Those remain required dependencies when the corresponding hardware and build infrastructure are available.

## Reproducibility

The M80 userspace binary was statically rebuilt with GCC using `-O2 -Wall -Wextra -Werror -Wno-cpp -static`, the FAISAL UAPI and service include paths, and `-lcrypto -ldl -lpthread`. The QEMU harness uses `qemu-system-x86_64`, two virtual CPUs, TCG, 768 MiB RAM, the recovered FAISAL `bzImage`, and a BusyBox initramfs. The harness exits successfully only after checking boot, selftest, and aggregate return markers.

## References

[1]: `M80-STRESS-FAILURE-DESIGN.md` — M80 scope, scenarios, failure model, and evidence limits.
[2]: `tools/faisal-stress/faisal_stress_service.c` — bounded stress coordinator implementation.
[3]: `tools/testing/selftests/agi_cross_subsystem_stress_test.c` — executable M80 acceptance test.
[4]: `tools/faisal-build/run_cross_subsystem_stress_qemu.sh` — QEMU boot and marker-validation harness.
[5]: `tools/testing/selftests/agi_end_to_end_test.c` — validated M76 completion contract used to correct M80 composition validation.
