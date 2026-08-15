# FAISAL M83 — CogOS Atom Control-Plane Module

## Summary

This milestone implements the attached CogOS kernel-module specification as a **FAISAL-compatible experimental loadable kernel module**. The module is built against FAISAL’s Linux v7.2-rc7 source and recovered build output. It provides bounded atom metadata, fixed-point attention values, an RCU-safe lookup path, slab allocation, a modern shrinker, a controlled scheduler thread, and a private character-device ioctl interface.

The module does not turn the Linux kernel into a semantic reasoning engine. It stores only bounded metadata. Model execution, embeddings, natural-language interpretation, semantic memory, source verification, privileged policy, and model authority remain in userspace.

## Delivered files

| File | Purpose |
|---|---|
| `tools/cog-kernel/cog_kernel.c` | Complete GPL kernel module |
| `tools/cog-kernel/Makefile` | Out-of-tree Kbuild recipe with strict warnings |
| `tools/cog-kernel/cog_tester.c` | Static ioctl validation tester |
| `tools/cog-kernel/run_cog_test.sh` | Host load/unload runner; returns 77 when root is unavailable |
| `tools/faisal-build/run_cog_kernel_qemu.sh` | FAISAL QEMU module insertion and unload harness |
| `tools/cog-kernel/COGOS-FAISAL-DESIGN.md` | Architecture and compatibility deviations |
| `tools/cog-kernel/COGOS-FAISAL-SECURITY-REVIEW.md` | Security review and evidence limits |

## Implemented ABI

`COG_LEARN` creates a concept, relation, or sensorimotor metadata atom and returns a nonzero random UUID. `COG_THINK` returns the atom type, fixed-point STI/LTI values, and bounded name. `COG_FOCUS` adds 10000 milli-units, representing the attachment’s requested `+10.0`, with saturation at the configured maximum. Unknown commands are rejected with `ENOTTY`.

The attachment requested floating-point STI/LTI fields. The module intentionally uses `u32` fixed-point milli-units because floating-point operations are not permitted in normal Linux kernel code. The attachment also requested `register_shrinker`; FAISAL uses the current target kernel’s `shrinker_alloc`/`shrinker_register`/`shrinker_free` lifecycle. The shrinker reports evicted atom objects, not pages, because the registered reclaimable object is an atom metadata object.

## Validation

| Test | Result |
|---|---:|
| Strict module build | Passed with `-Wall -Werror -Wno-declaration-after-statement` |
| Static userspace tester build | Passed |
| QEMU module insertion | Passed |
| Device-node creation | Passed |
| `COG_LEARN` | Passed |
| `COG_THINK` | Passed |
| `COG_FOCUS` and post-focus read | Passed, 1000 → 11000 milli-units |
| Malformed ioctl rejection | Passed with `ENOTTY` |
| Module unload | Passed |
| Attention drift disabled QEMU | Passed |
| Attention drift enabled QEMU | Passed |
| Four smoke runs | 4/4 passed |

Smoke elapsed times were 6304, 6175, 6280, and 6168 ms. The mean was 6231.7 ms and the range was 136 ms. These are complete QEMU harness timings, not isolated kernel performance measurements.

## Security posture

All ioctl input uses `copy_from_user` and output uses `copy_to_user`. Types, reserved fields, names, and UUIDs are validated. Hash mutation uses an IRQ-safe spinlock. Lookup uses RCU and a reference count. Removal uses RCU-safe hash deletion and deferred freeing. Module exit stops the scheduler, frees the shrinker, unlinks all atoms, waits for RCU callbacks, and destroys the slab cache.

The module contains no model invocation, command execution, network access, filesystem policy change, capability grant, or privileged action authorization. A model cannot cause a privileged kernel action merely by requesting `COG_FOCUS`.

## Evidence limits

This is an experimental control plane, not a production AtomSpace or complete AGI kernel. The milestone does not claim semantic reasoning, human-like cognition, embeddings, knowledge-graph quality, retraining, consciousness, high-scale AtomSpace performance, production multi-tenant isolation, KASAN/KCSAN/UBSAN/lockdep coverage, syzkaller coverage, randomized ioctl fuzzing, or physical hardware validation. The FIFO scheduler priority and global hash-table lock require future scalability and starvation benchmarks before production integration.
