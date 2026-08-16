# FAISAL M89: Concurrent RV Bridge Sanitizer Validation

**Milestone status:** Bounded sanitizer validation passed; ready for integration review

**Base:** Linux v7.2-rc7

**M88 dependency:** `FAISAL-M88` kernel Runtime Verification signal bridge

## Summary

M89 adds executable concurrency validation for the M88 bridge. Eight userspace workers repeatedly create, configure, subscribe, and release lifecycle sessions while two kernel workers emit direct bridge observations to the subscribed session. The test validates provenance, event-mask isolation, session lifetime, and report-path concurrency under Generic KASAN+lockdep and strict KCSAN+lockdep kernels.

The M89 test fixture is deliberately separate from the M88 `rv_react()` callback fixture. An initial attempt to invoke `rv_react()` from arbitrary kthreads triggered a valid lockdep invalid-wait-context warning in the upstream reactor wait-map path. The test was corrected by directly exercising the exported observation bridge from process-context kernel workers; no lockdep diagnostic was suppressed. M88 continues to cover the reactor callback path in a validation kernel.

## Implemented files

| File | Role |
| --- | --- |
| `tools/faisal-rv/faisal_rv_bridge_stress_fixture.c` | Bounded two-thread direct bridge report stimulus |
| `tools/testing/selftests/agi_rv_bridge_concurrency_test.c` | Eight-worker lifecycle, provenance, and isolation selftest |
| `tools/faisal-build/run_rv_bridge_sanitizer_qemu.sh` | Tracefs, readiness, QEMU, sanitizer, and diagnostic gate |
| `tools/faisal-rv/Makefile` | Kbuild target for the stress fixture |
| `M89-RV-BRIDGE-SANITIZER-DESIGN.md` | Architecture and test-boundary rationale |
| `M89-SECURITY-REVIEW.md` | Threat model, finding correction, and residual risk |
| `M89-BENCHMARKS.md` | Functional and sanitizer benchmark evidence |

## Verification record

| Gate | Result | Evidence |
| --- | --- | --- |
| Strict userspace selftest build | Passed | Harness compile with `-Wall -Wextra -Werror -static -pthread` |
| M89 fixture module build | Passed | KASAN and KCSAN module build logs |
| Normal functional smoke | Passed 3/3 | `m89-normal-smoke.tsv` |
| Generic KASAN + lockdep | Passed | 2-vCPU QEMU run, 21 records, no diagnostics |
| Strict KCSAN + lockdep | Passed | 1-vCPU QEMU run, 11 records, no diagnostics |
| Capability isolation | Passed in all final runs | `M89_CAPABILITY_FILTER_OK unsubscribed=1` |
| Provenance validation | Passed in all final runs | `M89_CONCURRENT_PROVENANCE_OK` |
| Targeted source security scan | Passed | `m89-security-scan.txt` |
| Diff hygiene | Passed | `git diff --check` |

## Acceptance scope

M89 is accepted as bounded sanitizer coverage for the M88 bridge after the invalid test-context finding was corrected. It is not a claim of race freedom, production readiness, long-duration soak coverage, hardware scalability, physical scheduler-stall generation, hardware-backed attestation, automatic repair, or upstream Linux performance improvement. The complete FAISAL program remains active and not operationally complete.

## References

[1]: `M89-RV-BRIDGE-SANITIZER-DESIGN.md` — workload, synchronization, and fixture boundary.
[2]: `M89-SECURITY-REVIEW.md` — security analysis and corrected finding.
[3]: `M89-BENCHMARKS.md` — measurements and limitations.
[4]: `tools/faisal-build/evidence/m89-kasan-qemu.log` — final KASAN+lockdep runtime output.
[5]: `tools/faisal-build/evidence/m89-kcsan-qemu.log` — final KCSAN+lockdep runtime output.
