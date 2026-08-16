# FAISAL industry-readiness research checkpoint

**Access date:** 2026-08-16.

## Linux engineering and testing

The official Linux development-process guidance describes a review-oriented lifecycle in which patches require problem specification, subsystem discussion, code checking, documentation, patch preparation, review, and follow-through rather than compilation alone [1]. The official kernel testing guide distinguishes KUnit white-box in-kernel unit tests from userspace kselftests for exposed interfaces and whole-feature behavior. It also identifies KCOV for fuzzing coverage, KASAN for invalid memory access, KCSAN for races, UBSAN for undefined behavior, KFENCE for low-overhead memory detection, lockdep for locking, Runtime Verification for selected behaviors, and Sparse, Smatch, and Coccinelle for static analysis [2].

FAISAL currently has strong userspace service and QEMU evidence, but the audit must verify whether each kernel modification has matching KUnit or kselftest coverage, whether sanitizer-enabled kernels were actually booted, whether KCOV or syzkaller is configured, and whether Sparse/Smatch/Coccinelle are available. Existing 23-harness passes do not substitute for all of these layers.

## Kernel self-protection

Linux kernel self-protection sets a high bar: protections should be effective, enabled by default, low-impact, debuggable, and tested [3]. The guidance covers strict kernel and module RWX, SMEP/SMAP or architecture equivalents, reduced syscall and module attack surfaces, stack and heap integrity, integer overflow defenses, KASLR, address-exposure control, initialization and poisoning, and protection against unprivileged module loading [3]. The Kernel Self-Protection Project’s recommended settings include strict RWX, stack protector, hardened usercopy, slab hardening, page-table checks, init-on-alloc/free, fortify, UBSAN bounds, KFENCE, randomization, seccomp, Landlock, Yama, lockdown, signed modules, IOMMU strict mode, and restrictive runtime sysctls [4].

FAISAL must separate three profiles: development/debug, recovery/QEMU, and production hardened. A QEMU development configuration that omits Landlock, lockdown, signed modules, or other hardening cannot be labeled industry-ready production security. The final assessment must report exact configuration deltas and unavailable hardware-dependent controls.

## Reproducible supply chain

Reproducible Builds defines an independently verifiable source-to-binary path. It requires a deterministic build, recorded or predefined tools and environment, and a way for independent parties to recreate and compare outputs [5]. This is stronger than recording a compiler version or a checksum produced by the same build host.

SLSA is an industry supply-chain framework organized around increasing security guarantees and provenance; the older v1.0 page is retired and points to the current v1.2 documentation [6]. FAISAL’s industry audit therefore needs source pinning, dependency/license inventory, build provenance, SBOM, artifact signatures, independent rebuild comparison, and release/rollback metadata. A Git tag alone is not a complete supply-chain attestation.

## Secure development practice

NIST SP 800-218 SSDF v1.1 recommends a common set of high-level secure-development practices that can be integrated into an SDLC, including reducing vulnerabilities, mitigating impact, addressing root causes, and communicating security practices to suppliers and consumers [7]. FAISAL’s governance loop covers research, implementation, tests, security review, benchmark, and rollback, but the audit must check for vulnerability intake and response, dependency tracking, release signing, SBOM, secure build isolation, code review evidence, and incident/revocation procedures.

## References

[1]: https://docs.kernel.org/process/development-process.html — Linux kernel development process guide.

[2]: https://docs.kernel.org/dev-tools/testing-overview.html — Linux kernel testing guide.

[3]: https://docs.kernel.org/security/self-protection.html — Linux Kernel Self-Protection documentation.

[4]: https://kspp.github.io/Recommended_Settings.html — Kernel Self-Protection Project recommended settings.

[5]: https://reproducible-builds.org/ — Reproducible Builds project and requirements.

[6]: https://slsa.dev/spec/v1.2/ — Current SLSA specification documentation.

[7]: https://csrc.nist.gov/pubs/sp/800/218/final — NIST SP 800-218 SSDF v1.1.
