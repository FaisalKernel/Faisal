# FAISAL Independent External Security Review

FAISAL treats an external security review as an **independent assurance activity**, not as another internal checklist. Internal threat models, scanners, fuzzing, KASAN/KCSAN/lockdep runs, QEMU regressions, and project-authored security reviews are preparation evidence. They do not constitute independent approval.

## Independence contract

The reviewer must be an identified external organization or individual with qualification evidence, a signed scope, an engagement identifier, and a conflict-of-interest declaration. The reviewer must explicitly attest that they are independent of the FAISAL project team. Project maintainers, implementers, model outputs, self-authored reports, or unlabeled synthetic fixtures cannot satisfy this requirement.

## Required review scope

The review must cover kernel UAPI and lifecycle paths; capability and provenance security; memory, scheduling, and resource controls; replication TLS and trust providers; accelerator, IOMMU, DMA, and driver boundaries; deployment, migration, and rollback; and userspace services and supply-chain interfaces. The reviewer must retain methodology, test evidence, source revision, artifact digest, and tool-version provenance.

## Findings and disposition

Every finding requires an identifier, severity, status, accountable owner, and evidence. Critical and high findings must be closed, fixed, or explicitly dispositioned according to the release policy before production approval. Closed or fixed findings require retest evidence. Accepted risks require accountable risk acceptance and an expiry. A zero-finding report is still represented as an explicit signed finding ledger entry rather than an absent field.

The final disposition must bind the recommendation to the exact source revision and artifact digest reviewed. The signed report must state residual risk and that final retest is complete. The production gate rejects reports that are stale, self-reviewed, incomplete, unsigned, bound to another revision, or carrying unresolved critical/high findings.

## FAISAL evidence gate

`verify_external_security_review.py` validates the signed structured JSON report and detached signature. `run_production_release_gate.sh` requires this report in addition to the existing artifact, security, advisory, accelerator, replication, deployment-governance, and reproducibility evidence. The gate fails closed when the report is absent or when any independence, scope, findings, retest, disposition, freshness, signature, or source-binding requirement is not satisfied.

The repository may prepare the review package, but it must not create a synthetic report and label it external. The current sandbox can validate the gate with synthetic fixtures only; it cannot close the blocker.

## References

[1] [NIST SP 800-218, Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)

[2] [CISA Secure by Design](https://www.cisa.gov/securebydesign)

[3] [Linux Kernel Security Bugs](https://docs.kernel.org/process/security-bugs.html)
