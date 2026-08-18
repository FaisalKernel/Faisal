# Independent external security review research — 2026-08-18

## NIST SP 800-218 SSDF

Source: https://csrc.nist.gov/pubs/sp/800/218/final

NIST describes SSDF as a set of high-level secure software development practices that can be integrated into an SDLC to reduce vulnerabilities, mitigate the impact of undetected vulnerabilities, address root causes, and provide a common vocabulary for supplier and management activities. FAISAL’s review package must therefore expose its security requirements, threat model, source/build/test evidence, vulnerability process, and remediation accountability to an independent reviewer.

## CISA Secure by Design

Source: https://www.cisa.gov/securebydesign

CISA states that technology providers should take executive-level ownership of product security and prioritize security as a core product requirement. FAISAL must keep independent reviewer identity, qualification, conflicts, scope, findings, severity, remediation, retest, and release disposition separate from the project implementation team. Internal tests and self-authored security reviews are preparation evidence, not independent approval.

## Linux security process

Source: https://docs.kernel.org/process/security-bugs.html

Linux directs security reports to affected subsystem maintainers and the kernel security team and distinguishes vulnerability intake from public disclosure. FAISAL’s review package must include its CVE response process, private-report handling, upstream coordination, and evidence-retention path.

## M173 design conclusion

The missing capability is not another internal security document. It is a signed, source-bound review package and fail-closed disposition gate that rejects self-review, project-affiliated reviewers, missing scope, unsigned findings, unresolved critical/high findings, stale retests, and releases that do not bind the reviewer’s disposition to the exact candidate revision and artifact digest.

## M176 authoritative-source confirmation

The official [NIST SP 800-115 publication page](https://csrc.nist.gov/pubs/sp/800/115/final) states that the guide assists organizations in planning and conducting technical security tests and examinations, analyzing findings, and developing mitigation strategies. The [NIST Cybersecurity and Privacy Reference Tool](https://csrc.nist.gov/projects/cprt/catalog) identifies the current SP 800-53 assessment, authorization, and monitoring control family and records the 5.2.0 release. The [CISA Secure by Design](https://www.cisa.gov/securebydesign) guidance says security should be treated as a core product requirement and that technology providers should take ownership of product security.

These sources support the existing M173 boundary and the M176 implementation: a reviewer handoff must be bound to the exact candidate, include a defined scope and methodology, capture findings and mitigation/retest evidence, and retain an accountable final disposition. None of these sources permits FAISAL to claim that an internal test, model output, or self-review is an independent assessment.

## M176 implementation conclusion

M176 adds a reproducible external-review candidate package, a package-manifest hash reference, a separate external reviewer public-key requirement, reviewer-key fingerprint binding, signed-final-report and signed-disposition attestations, and fail-closed package/candidate mismatch checks. This closes the **review-readiness and evidence-integrity gap**. It cannot create an independent reviewer, independent findings, remediation retests, residual-risk acceptance, or production approval; those remain external execution requirements.
