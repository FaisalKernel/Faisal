# FAISAL M89 RV Bridge Sanitizer Security Review

**Status:** Passed for the bounded validation environment, with one corrected test-design finding

## Scope

This review covers the M89 concurrent bridge fixture, lifecycle selftest, sanitizer QEMU harness, and the M88 bridge code exercised by the workload. It does not elevate the validation fixture into a production monitor or change the M88 authorization boundary.

## Finding and correction

The first stress-fixture design invoked `rv_react()` from arbitrary kernel kthreads. The KASAN+lockdep run reported an upstream invalid wait context: `rv_react_map` was held while an hrtimer lock was acquired during interrupt exit. This was a valid lockdep finding in the test stimulus, not evidence of an M88 bridge registry race. The test was corrected by removing that arbitrary-context `rv_react()` call from M89. M88’s separate deterministic fixture continues to exercise the RV reactor callback path in a validation kernel; M89 directly invokes the exported bridge report function from concurrent kernel threads to validate the bridge contract in an appropriate process context.

The failed run is retained as diagnostic evidence in the build workspace and is not presented as a pass. The final KASAN and KCSAN runs use the corrected fixture and contain no KASAN, KCSAN, lockdep, kernel-warning, or RCU diagnostic markers.

## Threat model and controls

A malicious lifecycle client may attempt to receive another session’s RV observations, race close against report delivery, or create malformed session state. A compromised userspace supervisor may misinterpret an observation as authorization. A malicious validation module may attempt to misuse the fixture boundary.

| Threat | M89 control | Result |
| --- | --- | --- |
| Report delivered to unsubscribed session | Existing event-mask check is exercised with a persistent unsubscribed descriptor | `M89_CAPABILITY_FILTER_OK unsubscribed=1` |
| Session lifetime race | Eight workers repeatedly open, configure, and release sessions while two kernel threads report | KASAN/KCSAN+lockdep runs pass |
| Test stimulus hides an upstream lock issue | M88 callback fixture and M89 direct bridge fixture are separated; lockdep is not disabled | Invalid-context finding corrected, final sanitizer runs clean |
| Fixture grants authority | Fixture emits only `agi_lc_rv_report()` observations and has no capability or repair path | Observation-only |
| Process execution or model authority in added code | Added/modified M89 lines scanned for high-risk process, privilege, user-copy, and model-authority patterns | Targeted scan passed |
| Readiness race loses the first event | Explicit marker plus barrier; no fixed-delay assumption | Three normal smoke passes and sanitizer passes |

## Lifetime and locking review

The M88 bridge walks `agi_lc_rv_sessions` under `agi_lc_rv_sessions_lock`. Session registration and removal use that same registry lock. Per-session record updates use the existing `queue_lock`; the report path does not retain a session reference after the registry lock is released. M89’s concurrent open/release workload is designed to exercise this ordering and would expose a use-after-free or locking defect through KASAN or lockdep.

The M89 fixture waits for all report workers to finish before its module initialization returns. This prevents the module text or static monitor state from being released while a worker remains active. The userspace selftest joins all lifecycle workers before closing its persistent descriptors and reports failure if any worker cannot complete its session lifecycle.

## Residual risks

The test environment is QEMU TCG and does not establish hardware-backed assurance. The direct bridge fixture uses a synthetic monitor name and status, so it validates source plumbing, provenance encoding, concurrency, and filtering rather than a physical RV monitor violation. The compact monitor hash is not a cryptographic identity. The test-hook export remains validation-only and should be disabled in production configurations.

The final evidence demonstrates bounded sanitizer coverage, not proof of race freedom or absence of all kernel defects. The existing Linux and FAISAL kernel remain a large trusted computing base; normal module-signing, lockdown, LSM, capabilities, namespaces, and deployment approval policies remain necessary.

## Decision

M89’s bounded security gate passes after correcting the invalid test-context finding. The corrected direct bridge stress workload passes Generic KASAN+lockdep and strict KCSAN+lockdep QEMU validation, the normal-kernel smoke set passes three times, the targeted source scan finds no new high-risk patterns, and the event isolation boundary remains intact. The original lockdep finding is explicitly recorded as a test-design defect resolved by changing the fixture context, not by suppressing diagnostics.

## References

[1]: `M89-RV-BRIDGE-SANITIZER-DESIGN.md` — test architecture and corrected fixture boundary.
[2]: `M88-SECURITY-REVIEW.md` — M88 trust model and observation-only policy.
[3]: `tools/faisal-build/evidence/m89-security-scan.txt` — targeted added-line scan.
[4]: `tools/faisal-build/evidence/m89-kasan-qemu.log` — corrected KASAN+lockdep runtime evidence.
[5]: `tools/faisal-build/evidence/m89-kcsan-qemu.log` — corrected KCSAN+lockdep runtime evidence.
