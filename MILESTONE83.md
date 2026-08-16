# FAISAL M83 — Transactional Persistent-Memory Concurrency

## Status

M83 is validated as a **bounded userspace transactional layer integrated with the existing FAISAL persistent-memory service and ABI 37 lifecycle authorization**. It is not a new kernel-wide filesystem transaction primitive. The service adds a two-journal coordinator protocol, durable prepared/committed/aborted state, backup-based rollback, explicit crash injection, session reactivation, and concurrent read/write testing.

The implementation addresses a concrete M82 limitation: M82 could replay each journal independently, but it did not provide an atomic cross-journal outcome when a multi-memory update failed after one journal had been applied. M83 now exercises a two-operation transaction over separate persistent-memory journals and verifies that a crash after both operations have been applied restores both journals to their pre-transaction state.

## Implemented Artifacts

| Artifact | Purpose |
|---|---|
| `tools/faisal-memory/faisal_memory_transaction.[ch]` | Two-journal prepare/commit/recover protocol |
| `tools/faisal-memory/faisal_memory_service.[ch]` | Existing service plus explicit session reactivation helper |
| `tools/testing/selftests/agi_memory_transaction_test.c` | Executable transaction, replay, capability, and concurrency test |
| `tools/faisal-build/run_memory_transaction_qemu.sh` | Source-building QEMU harness |
| `tools/faisal-build/run_full_faisal_audit.sh` | Source rebuild and 22-harness regression runner |
| `M83-PERSISTENCE-RESEARCH.md` | Persistence semantics and design provenance |
| `tools/faisal-build/evidence/m83-*` | Validation, sanitizer, benchmark, regression, and security evidence |

## Acceptance Results

The final clean QEMU run passed duplicate-target input validation, prepared-state crash injection, rollback to both baseline journals, successful two-journal commit, journal replay, stale-capability denial, 16 concurrent writer operations per journal, 2,000 concurrent protected reads, and clean exit. The final tracked full regression passed **22/22 QEMU harnesses**, including the existing M71, M74, M82, and M81 paths.

The same M83 workload passed on the Generic KASAN + lockdep kernel with four virtual CPUs. A strict KCSAN + lockdep run with four virtual CPUs completed the test but emitted RCU starvation warnings under sanitizer instrumentation. An eight-vCPU KCSAN run completed with no RCU-stall, KCSAN, lockdep, Oops, panic, or KASAN signatures and is the recorded clean KCSAN result. The four-vCPU warning remains preserved in evidence and is not suppressed.

## Transaction Protocol

M83 writes a prepared coordinator manifest and a durable backup for every journal before applying operations through `fms_put`. Each service operation is preceded by `fms_reactivate`, which reattaches the current task to the session and selected memory agent owning that journal. The manifest becomes committed only after all operations succeed. A crash injected after the second journal operation leaves the manifest prepared; recovery restores every journal from its backup and marks the transaction aborted. Successful commits mark the manifest committed and remove backups.

## Security and Authority

M83 validates duplicate-target rejection, preserves existing FAISAL memory-record capability checks, and explicitly verifies stale-capability denial. It contains no process-launch, identity-changing, `ptrace`, `CAP_SYS_ADMIN`, model invocation, or model-authority primitive. Model output is not consumed by the transaction protocol and never becomes kernel authorization.

## Limitations

M83 is deliberately bounded to two journals and a userspace coordinator. It does not make kernel persistent-memory records, journal files, filesystem metadata, and power-loss behavior one hardware-atomic transaction. The protocol uses fixed paths and `fdatasync`; the Linux documentation notes that file synchronization does not necessarily synchronize containing directory entries [1]. M83 therefore does not claim crash consistency across arbitrary filesystem failures, power-loss durability on every filesystem, formal transaction correctness, distributed transactions, hardware-backed nonvolatile memory, or production readiness.

The concurrent read/write test uses an explicit pthread read/write lock around the existing service object. It validates service-level interleaving and kernel-backed operations but does not claim that unsynchronized access to the legacy `fms_service` structure is safe. KCSAN remains sampling-based, so a passing run is not proof of race freedom [2].

## References

[1]: https://man7.org/linux/man-pages/man2/fsync.2.html "fsync(2) — synchronize a file's in-core state with storage device"
[2]: https://docs.kernel.org/dev-tools/kcsan.html "Linux Kernel Concurrency Sanitizer documentation"
