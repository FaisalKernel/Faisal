# FAISAL Independent External Security Review

FAISAL treats an external security review as an **independent assurance activity**, not as another internal checklist. Internal threat models, scanners, fuzzing, KASAN/KCSAN/lockdep runs, QEMU regressions, and project-authored security reviews are preparation evidence. They do not constitute independent approval.

## Independence contract

The reviewer must be an identified external organization or individual with qualification evidence, a signed scope, an engagement identifier, and a conflict-of-interest declaration. The reviewer must explicitly attest that they are independent of the FAISAL project team. Project maintainers, implementers, model outputs, self-authored reports, or unlabeled synthetic fixtures cannot satisfy this requirement.

Production verification now requires a **separate external reviewer public key** through `FAISAL_EXTERNAL_SECURITY_REVIEW_PUBLIC_KEY`. The operator release key is not an external assessor identity. The completed report must include the SHA-256 fingerprint of that reviewer key and `signed_final_report: true`; the verifier checks the fingerprint against the supplied key and verifies the detached signature.

## Exact-candidate package

Prepare a reviewer-controlled package only after selecting the exact candidate source revision and artifacts:

```sh
python3 tools/faisal-build/prepare_external_security_review_bundle.py \
  --source-dir /home/ubuntu/agi-kernel/linux \
  --source-revision <exact-lts-or-release-source-revision> \
  --artifact /path/to/bzImage \
  --config /path/to/.config \
  --handoff-manifest /path/to/physical-accelerator-handoff.json \
  --runbook /home/ubuntu/agi-kernel/linux/FAISAL-EXTERNAL-SECURITY-REVIEW.md \
  --output-dir /path/to/external-security-review-package
```

The generator creates `review-package.json`, a tarball, SHA-256 records, the exact kernel artifact and configuration, source/provenance records, accelerator handoff manifest, the review runbook, validator, validator tests, release gate, and program state. It also creates a **template**; the template is not evidence and must not be labeled as a completed review.

The package manifest binds the following candidate identity fields: source revision, source-worktree provenance, artifact digest, configuration digest, build ID, and package ID. A completed report must reference the package ID and the SHA-256 of the exact package manifest. A mismatch is rejected.

## Required review scope

The review must cover kernel UAPI and lifecycle paths; capability and provenance security; memory, scheduling, and resource controls; replication TLS and trust providers; accelerator, IOMMU, DMA, and driver boundaries; deployment, migration, and rollback; and userspace services and supply-chain interfaces. The reviewer must retain methodology, test evidence, source revision, artifact digest, configuration digest, package manifest digest, and tool-version provenance.

## Findings and disposition

Every finding requires an identifier, severity, status, accountable owner, and evidence. Critical and high findings must be closed, fixed, or explicitly dispositioned according to the release policy before production approval. Closed or fixed findings require independent retest evidence. Accepted risks require accountable risk acceptance and an expiry. A zero-finding report is still represented as an explicit signed finding ledger entry rather than an absent field.

The final disposition must bind the recommendation to the exact source revision, artifact digest, and package reviewed. It must state residual risk, that final retest is complete, and `signed_by_reviewer: true`. The detached signature must be made with the independent reviewer key, not a project or operator key.

## Production verification

The validator can be run directly:

```sh
FAISAL_EXTERNAL_SECURITY_REVIEW=/path/to/completed-review.json \
FAISAL_EXTERNAL_SECURITY_REVIEW_PACKAGE=/path/to/review-package.json \
FAISAL_SECURITY_REVIEW_PUBLIC_KEY=/path/to/external-reviewer-public.pem \
FAISAL_EXPECTED_SOURCE_REV=<exact-source-revision> \
python3 tools/faisal-build/verify_external_security_review.py
```

The production release gate requires the same three external-review inputs through `FAISAL_EXTERNAL_SECURITY_REVIEW`, `FAISAL_EXTERNAL_SECURITY_REVIEW_PACKAGE`, and `FAISAL_EXTERNAL_SECURITY_REVIEW_PUBLIC_KEY`. It fails closed when the report or package is absent, when the reviewer is not independent, when the reviewer key fingerprint does not match, when the scope or findings ledger is incomplete, when a report is stale or signed by the wrong key, when the candidate identity differs, when retests or residual-risk disposition are missing, or when model output is treated as authority.

The repository may prepare the package and validate synthetic fixtures, but it must not create a synthetic report and label it external. The current sandbox cannot provide a genuinely independent qualified reviewer, external findings, remediation retests, residual-risk acceptance, or signed production disposition. Therefore this implementation closes the **review-readiness and evidence-integrity gap** but does not close the external-review execution blocker.

## References

[1] [NIST SP 800-115, Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)

[2] [NIST Cybersecurity and Privacy Reference Tool, SP 800-53 release 5.2.0](https://csrc.nist.gov/projects/cprt/catalog)

[3] [CISA Secure by Design](https://www.cisa.gov/securebydesign)

[4] [Linux Kernel Security Bugs](https://docs.kernel.org/process/security-bugs.html)
