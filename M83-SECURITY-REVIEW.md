# M83 Security Review — Transactional Persistent Memory

## Scope

This review covers the M83 transaction coordinator, the `fms_reactivate` helper, the selftest, and the QEMU harness. It also considers the existing ABI 37 persistent-memory capability checks used by `fms_put` and `fms_test_stale_capability`.

## Threat Model and Controls

| Threat | Control | Observed result |
|---|---|---|
| Duplicate or ambiguous transaction target | Reject duplicate journal paths before backups or writes | `M83_TRANSACTION_INPUT_VALIDATION_OK` |
| Partial cross-journal update | Durable prepared manifest plus per-journal backups | Both journals restored after failure after operation two |
| Replaying incomplete transaction as committed | Recovery accepts only `PREPARED`, restores backups, writes `ABORTED` | `M83_CRASH_ROLLBACK_OK state=3` |
| Forged persistent-memory authority | Existing kernel record capability remains required; stale handle is mutated and tested | `M83_CAPABILITY_ISOLATION_OK` |
| Wrong current session after multiple service opens | `fms_reactivate` reattaches the owning session and selected agent | Left/right operations pass without weakening checks |
| Concurrent service-structure corruption | Explicit pthread read/write lock around shared service objects | 16 writes and 2,000 reads pass |
| Malicious model output | No model or planner output enters the transaction API | Model output remains non-authoritative |
| Privileged process escape | Source scan for process launch, identity change, ptrace, and `CAP_SYS_ADMIN` | `M83_SECURITY_SCAN=PASS` |

## Crash and Durability Risks

The protocol uses fixed journal and manifest paths with `fdatasync`. The Linux man-pages documentation distinguishes data synchronization from full metadata synchronization and warns that synchronizing a file does not necessarily synchronize its containing directory entry [1]. M83 does not use path replacement as a hidden atomicity claim and does not present `fdatasync` as a power-loss proof.

A failure while creating a backup, writing the prepared manifest, or applying an operation returns an error. The current recovery path is designed for a valid prepared manifest and valid backups; corruption of the coordinator manifest or backup itself is reported rather than guessed through. This is the correct fail-closed behavior for persistent state.

## Sanitizer Findings

Generic KASAN + lockdep passed the final M83 workload on four vCPUs without KASAN, lockdep, Oops, or panic signatures. Strict KCSAN + lockdep completed on four vCPUs but emitted RCU starvation warnings caused by the heavily instrumented environment. An eight-vCPU run completed without RCU stalls or sanitizer/lockdep signatures and is the clean KCSAN result. The four-vCPU evidence is retained rather than suppressed.

## Residual Risk

M83 does not provide cryptographic authentication of journal paths, does not protect against a malicious process with write access to the journal directory, does not cover arbitrary filesystem or power-loss behavior, and does not provide distributed commit. The kernel capability remains the authority for persistent-memory records; the transaction manifest is userspace metadata and cannot grant a capability.
