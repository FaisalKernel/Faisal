# FAISAL Industry-Readiness Audit

**Project:** FAISAL AGI-native Linux kernel

**Audit date:** 2026-08-16

**Auditor:** Manus AI

**Source head audited:** `4de2a3bf17984ad858aa7fb4ea27fd33f968e754`, governance follow-up after `FAISAL-M102`

**Kernel base:** Linux `v7.2-rc7`, ABI 38

## Executive determination

FAISAL is an **advanced, executable research and pre-production prototype**, not an industry-ready production operating-system release. The project now demonstrates a substantial native AGI control plane: persistent lifecycle sessions, agent identity, lineage, capability-scoped authority, memory/checkpoint primitives, causal and verified-effect records, deadline urgency, runtime verification, provider gates, deployment supervision, browser/research services, and network-isolated nondeterministic adapters. Those claims are supported only for the exercised ABI paths and test fixtures; they do not imply consciousness, foundation-model retraining, unrestricted autonomy, universal accelerator support, or complete kernel security.

The audit found and addressed several high-value engineering gaps. The aggregate suite now covers M101 scheduler urgency, M102 nondeterministic adapters, and a new randomized lifecycle UAPI fuzz smoke. The previously failing cog-kernel harness was diagnosed as a stale kernel-image/module `vermagic` mismatch and repaired by rebuilding the boot image from the same output tree before building the external module. A deterministic build-manifest/SPDX SBOM/checksum generator and a hardened production configuration generator were added. The lifecycle driver’s current-head Sparse errors were fixed with RCU-safe parent traversal and typed parent-ID helpers.

The remaining release blockers are material: the release base is a release candidate rather than a stable or long-term-support kernel; production artifacts are not independently rebuilt or trusted-signed; current-head KASAN/KCSAN/lockdep/KCOV coverage is not yet rerun after the latest changes; the project has no syzkaller campaign; whole-file checkpatch debt is substantial; real accelerator and multi-tenant hardware validation is unavailable; and long-duration fault-injection, rollback, monitoring, and vulnerability-response operations are not proven.

> **Readiness verdict:** FAISAL passes a strengthened prototype regression gate, but it must not be marketed or deployed as a production-secure kernel until the P0 and P1 residual gaps below have independently verifiable evidence.

## Audit framework

The audit uses Linux’s own development and testing expectations together with kernel self-protection, reproducible-build, secure-development, and supply-chain guidance. Linux’s testing guide separates KUnit white-box tests from kselftests for exposed interfaces and identifies KASAN, KCSAN, UBSAN, KFENCE, lockdep, KCOV, Sparse, Smatch, and Coccinelle as complementary tools [1]. Linux self-protection guidance requires attack-surface reduction, strict memory permissions, memory integrity, address randomization, information-exposure controls, and tests [2]. The Kernel Self-Protection Project publishes a conservative hardening profile including strict RWX, stack protection, hardened usercopy, allocator hardening, init-on-alloc/free, seccomp, Landlock, lockdown, signed modules, IOMMU strictness, and restrictive runtime settings [3]. Reproducible Builds requires deterministic inputs, recorded tools, and independent rebuild comparison [4]. NIST SSDF provides a secure-development vocabulary covering vulnerability reduction, mitigation, root-cause correction, and supplier communication [5].

## Measured evidence collected

| Evidence | Result | Interpretation |
|---|---:|---|
| Standard FAISAL kernel build after the Sparse fixes | Pass | `build/recovered/arch/x86/boot/bzImage` rebuilt from the audited head. |
| Aggregate QEMU regression suite | **26/26 pass** | Includes the prior 23 paths, repaired cog-kernel path, M101, M102, and lifecycle UAPI fuzz. This is a bounded regression gate, not proof of complete security. |
| Cog-kernel failure diagnosis | Repaired | The old image expected `7.2.0-rc7-gba8fa4908177-dirty`; the module was `7.2.0-rc7-g4de2a3bf1798`. The harness now incrementally refreshes the image before module construction. |
| Lifecycle UAPI fuzz smoke | Pass | 4,096 iterations per QEMU boot, two ioctl calls per iteration: 8,192 calls, all normal rejections, no kernel fault markers. |
| Bounded reliability soak | Pass | Three independent QEMU boots, 16,384 iterations per boot, 98,304 total ioctl calls, 4–5 seconds wall time per round, no detected kernel fault markers. This is not a multi-hour or hardware soak. |
| Current-head Sparse | Pass with two warnings | Upstream Sparse `v0.6.5-rc1`, commit `37156835e3d725b6d750f000be33ba3814bb2310`; no address-space errors remain. Warnings concern large fixed-size `memset()` operations at driver lines 4771 and 9446. |
| Current-head strict compilation | Pass | Lifecycle driver rebuilt with Kbuild after the Sparse changes. |
| Full-file checkpatch | Fails | The legacy FAISAL driver reports 317 errors and 95 warnings; the UAPI header reports additional style findings. This is a reviewability and upstreamability blocker, not by itself a runtime failure. |
| Hardened production profile build | Pass | Derived profile built a separate `bzImage` with built-in lifecycle driver, Landlock, lockdown confidentiality, seccomp, strict page-table checks, allocator initialization/hardening, no modules, no kexec, and no test instrumentation. |
| Hardened-profile QEMU fuzz | Pass with environment warning | The same 4,096-iteration fuzz gate passed. QEMU emitted ACPI AML loop-timeout messages during shutdown; they were retained and are not treated as a clean hardware-quality signal. |
| Supply-chain artifacts | Partial pass | Manifest, SPDX 2.3 SBOM, and SHA-256 checksums are generated. No trusted release signature or independent rebuild comparison is present. |
| Sanitizer evidence | Historical/bounded | Earlier milestone evidence covers selected paths. Current-head post-M102 sanitizer runtime coverage is not established. M100/M102 explicitly record ASan/TSan runtime limitations under the production seccomp child policy. |
| Hardware/provider coverage | Not demonstrated | Accelerator interfaces remain provider- and hardware-gated; no real GPU/NPU/RDMA/DMA/IOMMU isolation evidence exists in this environment. |

## Severity-ranked requirements matrix

| Area | Status | Severity | Audit finding and acceptance requirement |
|---|---|---:|---|
| Kernel source foundation | Partial | P0 | `v7.2-rc7` is current mainline as of the captured kernel.org page, while `7.1.8` is stable and `6.18.44` is longterm [6]. A production branch must be rebased or forward-ported to a stable/LTS line and carry a documented security-update policy. |
| FAISAL native lifecycle and authority model | Pass for exercised paths | P1 | ABI 38 paths have extensive QEMU evidence. Model output is not authority; supervisor and operator gates remain required. Add independent review and broader malformed/concurrent coverage before release. |
| Upstream coding quality | Fails | P0 | Whole-file checkpatch debt is too high for industry review. Acceptance requires a staged cleanup of new FAISAL code, zero unreviewed errors in touched code, and a documented waiver list for intentional kernel style exceptions. |
| Static analysis | Partial | P1 | Upstream Sparse now runs and has only two large-memset warnings. Smatch and Coccinelle are not installed or executed. Acceptance requires Sparse, Smatch, Coccinelle, compiler analyzer, and warning triage in CI. |
| Memory/concurrency safety | Partial | P0 | Historical KASAN/KCSAN/lockdep evidence exists, but current-head changes need fresh instrumented builds and QEMU runs. Passing sampled KCSAN is not race freedom. Acceptance requires current-head KASAN, KCSAN, lockdep, UBSAN, and fault-injection evidence. |
| UAPI fuzzing | Improved, incomplete | P1 | The new deterministic bounded fuzz gate reaches the real `/dev/agi_lifecycle` device and survives 98,304 calls in the soak. KCOV/syzkaller coverage and corpus minimization are still absent. |
| Aggregate regression | Pass with centralized diagnostic scanning | P1 | The suite now has 26 harnesses and no known harness failure. Per-harness logs are cleared before execution and scanned for kernel fault and warning markers; the gate also has timeout and retry behavior. This remains a bounded regression gate, not proof of complete security. |
| Supply-chain provenance | Partial | P0 | A deterministic manifest, SPDX SBOM, and checksums now exist. A separate independent build completed but produced a different bzImage hash because build-version/timestamp metadata was not pinned; a deterministic wrapper is now present, but a clean two-build byte comparison remains a release blocker. Artifacts are unsigned. |
| Production hardening | Partial | P0 | The generated profile builds and boots. The normal recovered profile still has a broader development configuration, and hardware-dependent runtime controls are not proven. Release artifacts must use the hardened profile and validated boot/runtime policy. |
| Vulnerability management | Missing as an operational gate | P0 | No complete CVE intake, upstream-watch, severity SLA, embargo handling, patch provenance, or release revocation procedure is evidenced. |
| Reliability and recovery | Partial | P1 | The bounded soak and existing checkpoint/recovery tests are useful. Multi-hour/day soak, memory pressure, fault injection, crash dump preservation, rollback, and restart supervision remain unproven. |
| Performance | Partial | P1 | M101 has measured scheduler evidence and earlier milestones contain targeted benchmarks. A complete upstream-versus-FAISAL suite for syscall, context switch, IPC, memory, scheduling tail latency, checkpoint, recovery, and multi-agent scale is absent. No unmeasured superiority claim is permitted. |
| Observability | Partial | P1 | FAISAL telemetry and kernel tracing hooks exist. End-to-end eBPF/perf dashboards, alert thresholds, cardinality control, retention, and operator runbooks are not demonstrated. |
| Hardware/provider integration | Gated | P0 for production claims | The accelerator contract is modular and correctly avoids fabricating hardware proof. Real GPU/NPU/RDMA/IOMMU/SR-IOV/reset/accounting validation is required for hardware-support claims. |
| Deployment and rollback | Partial | P0 | Independent supervisor and operator approval paths are represented. Signed release bundles, canary promotion, health gates, automatic rollback, revocation, and monitoring under real deployment conditions remain to be proven. |
| Documentation and reviewability | Partial | P1 | Architecture, security, milestone, and research documents are extensive. The audit report, production profile, and artifact scripts improve evidence organization, but APIs, failure matrices, and touched-code review debt remain. |

## Completed gap-filling changes in this audit

### Aggregate and harness integrity

`tools/faisal-build/run_full_faisal_audit.sh` now includes `run_scheduler_urgency_qemu.sh`, `run_nondeterministic_adapter_qemu.sh`, and `run_lifecycle_uapi_fuzz_qemu.sh`. `run_cog_kernel_qemu.sh` now rebuilds the current `bzImage` from the same `KBUILD_OUTPUT` before building `cog_kernel.ko`, eliminating the stale-image `vermagic` failure mode. The resulting aggregate run reached 26/26 passes.

### UAPI fuzzing and bounded soak

`tools/testing/selftests/agi_lifecycle_uapi_fuzz_test.c` uses a deterministic xorshift stream, bounded 4 KiB buffers, read-only/query commands, malformed command encodings, nonblocking device access, and normal errno accounting. It never treats random input as authority. `run_lifecycle_uapi_fuzz_qemu.sh` boots the real kernel and scans for kernel fault markers. `run_industry_soak_qemu.sh` repeats the QEMU workload across independent boots. These additions materially improve interface robustness evidence but are not a replacement for KCOV-guided syzkaller campaigns.

### Supply-chain evidence

`tools/faisal-build/generate_industry_artifacts.sh` emits a build manifest, SPDX 2.3 SBOM, and SHA-256 checksum list. It pins `SOURCE_DATE_EPOCH` to the source commit timestamp by default, records compiler and Make versions, includes configuration and artifact hashes, and explicitly reports that artifacts remain unsigned unless the release environment supplies a trusted signing key. This is an evidence generator, not a release authority.

### Hardened production profile

`tools/faisal-build/prepare_industry_production_config.sh` derives a separate profile without mutating the recovery build. It enables strict kernel protections, Landlock, lockdown confidentiality, seccomp, page-table checks, allocator initialization/hardening, and strict IOMMU defaults where supported; it disables modules, kexec, hibernation, and selected unnecessary attack surfaces while retaining the built-in AGI lifecycle driver. Kconfig dependencies can preserve some compatibility options; the normalized output, not the request, is authoritative.

### Sparse correctness fixes

The lifecycle driver’s current-head Sparse errors were caused by direct comparisons and dereferences of `__rcu` `real_parent` pointers and by passing `pid_t *` fields to a `u64 *` helper. The code now uses RCU-safe ancestry reads and typed helpers. Upstream Sparse reports no remaining address-space errors; two large fixed-size memset warnings remain for review.

## Release gates still required

A FAISAL production release should remain blocked until all P0 items have evidence. The minimum next sequence is a current-head sanitizer matrix, KCOV-enabled QEMU execution, a syzkaller-compatible description and campaign for the lifecycle UAPI, staged checkpatch cleanup, independent reproducible rebuilds, trusted signatures and verification, CVE/upstream tracking, a stable/LTS forward-port plan, and real hardware/provider qualification. Production deployment must continue to require both an independent trusted supervisor and explicit operator approval; an LLM response, model output, stored experience, or provider metadata must never substitute for those gates.

## References

[1]: https://docs.kernel.org/dev-tools/testing-overview.html — Linux Kernel Testing Guide.

[2]: https://docs.kernel.org/security/self-protection.html — Linux Kernel Self-Protection.

[3]: https://kspp.github.io/Recommended_Settings.html — Kernel Self-Protection Project Recommended Settings.

[4]: https://reproducible-builds.org/ — Reproducible Builds project.

[5]: https://csrc.nist.gov/pubs/sp/800/218/final — NIST SP 800-218 Secure Software Development Framework v1.1.

[6]: https://www.kernel.org/ — Linux Kernel Archives release table captured on 2026-08-16.
