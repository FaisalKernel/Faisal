# FAISAL M80 Security Review

## Review scope

This review covers the M80 stress coordinator, its selftest, and the QEMU harness. The review is limited to the code and execution evidence produced by this milestone. It does not certify the Linux kernel, the full FAISAL program, or any production deployment.

## Security properties reviewed

| Property | Implementation/evidence | Assessment |
|---|---|---|
| Model output is not authority | M80 invokes existing M76/M78 policy and approval paths; it does not convert text or model data into an ioctl authorization | Preserved |
| Independent approval path | M76 composition uses supervisor and operator approval fields with distinct nonces; M78 candidate approval includes supervisor, operator, integrity, and canary gates | Exercised through composed services |
| Malformed UAPI rejection | 256 deterministic mutations cover undersized request, invalid flags, and reserved-field violations; all were rejected | Passed: 256/256 |
| Capability and scope enforcement | M76 services execute lifecycle, memory, world, browser, IPC, reflection, and deployment operations through their existing scoped handles and kernel ioctl checks | Passed by M76 regression composition |
| Resource-state honesty | M80 rejects overlapping measured, unavailable, and unsupported resource masks and rejects bits outside the defined resource mask | Passed: 8/8 samples |
| Cancellation safety | Eight repeated M76 cancellation paths require a cancellation message identifier and do not accept a failed run as completed | Passed: 8/8 |
| Rollback safety | M78 canary failure is injected deterministically; rollback must reach `M78_STATE_ROLLED_BACK` before success | Passed: 2/2 |
| Provider honesty | M79 provider discovery and validation remain separate; unsupported provider state is propagated rather than converted to support | Passed: unsupported state propagated |
| Journal path isolation | M80 uses distinct bounded prefixes and mounts a private writable tmpfs in the QEMU guest | Exercised in QEMU |
| No panic/Oops in exercised path | Captured QEMU logs for M80 and the fifteen regression harnesses contained no panic, Oops, BUG, or general-protection marker | Passed for exercised path |

## Review findings

No critical security defect was found in the reviewed M80 changes. The implementation uses fixed upper bounds for all stress loops: 256 malformed requests, 8 resource samples, 3 compositions, and 8 cancellation runs. Input strings are copied with bounded `strncpy` calls, journal prefixes are written into fixed-size buffers with bounded `snprintf`, and file descriptors are closed on the visible error paths.

The M80 malformed-input test performs negative testing against the kernel UAPI and treats any unexpected successful ioctl as a failure. It does not grant a capability, bypass an approval gate, or interpret a model result as a security decision. The resource-pressure test preserves the distinction between measured, unavailable, and unsupported values and rejects ambiguous overlapping masks.

The rollback test only reports success after the deployment service reaches its explicit rolled-back state. The accelerator portion only reports the provider state returned by the provider-neutral validation service. This preserves the project’s non-fabrication rule that provider metadata is not hardware proof.

## Residual risks and required future work

M80 is not a substitute for KASAN, KCSAN, UBSAN, lockdep, syzkaller, randomized fuzzing, long-duration soak, hardware accelerator testing, or a full threat-model assessment of every upstream kernel subsystem. Those tools and environments were not available in the recovered build used for this milestone. The QEMU harness also uses a deterministic test fixture and does not model hostile multi-tenant hardware, DMA, firmware, SMI behavior, or real browser/network content.

The service-level loops are sequential rather than a high-contention concurrent stress workload. Future work should add sanitizer-enabled kernel builds, concurrent lifecycle and IPC stress, randomized structured input generation, persistent journal corruption testing, fault injection under memory pressure, and real provider validation without weakening the unsupported-state boundary.

## Review conclusion

M80’s exercised paths fail closed on malformed requests, ambiguous resource reports, incomplete cancellation, failed canaries, and unsupported provider evidence. The evidence supports bounded validation hardening only. It does not support claims of complete kernel security, race freedom, production readiness, or unrestricted autonomous operation.

## References

[1]: `M80-STRESS-FAILURE-DESIGN.md` — bounded failure model and evidence limits.
[2]: `tools/faisal-stress/faisal_stress_service.c` — reviewed implementation.
[3]: `tools/faisal-coordinator/faisal_coordinator_service.c` — M76 approval, capability, and recovery composition.
[4]: `tools/faisal-deploy/faisal_deploy_supervisor.c` — M78 independent approval and rollback controls.
[5]: `tools/faisal-accelerator/faisal_accelerator_validation.c` — M79 provider-neutral hardware-gated validation.
[6]: `tools/faisal-build/run_cross_subsystem_stress_qemu.sh` — QEMU isolation and marker checks.
