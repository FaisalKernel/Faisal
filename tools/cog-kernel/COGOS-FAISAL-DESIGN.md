# CogOS Kernel Module for FAISAL

## Purpose

This artifact implements the attachment’s CogOS control-plane concept as an experimental loadable kernel module for FAISAL’s Linux v7.2-rc7 base. It provides bounded atom metadata, attention scores, RCU-safe lookup, memory-pressure eviction, a controlled scheduler thread, and a character-device ioctl interface.

The module is **not** a semantic knowledge base, neural runtime, embedding store, or authorization engine. Model execution, semantic reasoning, natural-language interpretation, provenance verification, and privileged policy remain in userspace. The kernel stores only bounded metadata and enforces lifecycle and memory behavior.

## Compatibility decisions

| Attachment request | FAISAL implementation | Reason |
|---|---|---|
| Linux 6.x | Linux v7.2-rc7 source and recovered build output | FAISAL’s actual verified foundation is newer than the attachment target; the module uses the APIs present in the project source |
| `float` STI/LTI | `u32` fixed-point milli-units | Kernel floating-point use is not permitted; `10000` represents the attachment’s `+10.0` boost |
| `DECLARE_HASHTABLE(..., 20)` | `DEFINE_HASHTABLE(..., 20)` | The module owns one global table and uses the modern definition form |
| `register_shrinker` | `shrinker_alloc`, callback assignment, `shrinker_register`, `shrinker_free` | The target source uses the modern shrinker lifecycle |
| Shrinker returns pages | Shrinker returns evicted atom objects | Linux shrinker callbacks report reclaimable objects for the registered shrinker; an atom is metadata, not a page |
| Random attention drift | Bounded fixed-point drift using kernel random helpers, controlled by `attention_drift` module parameter | Keeps the requested stub behavior while allowing deterministic validation with `attention_drift=0` |
| High-priority scheduler | `kthread_run` followed by `sched_set_fifo` | Uses the scheduler helper present in the target source; the loop is bounded to 10 ms sleeps |
| Dynamic character device | `alloc_chrdev_region`, `cdev_add`, `class_create`, `device_create` | Standard current character-device lifecycle |
| Unsafe direct userspace access | `copy_from_user` and `copy_to_user` with validation | Required for kernel/user memory safety |

## Atom lifecycle

A `COG_LEARN` request validates the type and bounded NUL-terminated name, allocates an atom from the dedicated slab cache, assigns a nonzero random UUID, inserts it into the hash table under an IRQ-safe spinlock, and returns the UUID and initial fixed-point scores. A failed userspace copy-back removes the newly inserted atom before returning the error.

`COG_THINK` uses RCU lookup with a reference-count acquisition, takes the spinlock while copying mutable fields, releases the reference, and returns the atom snapshot. `COG_FOCUS` follows the same reference path and increases STI by 10000 with saturation at the fixed-point maximum.

The scheduler thread optionally applies a bounded random drift of at most two milli-units per tick. The validation harness disables drift for deterministic expected values and separately runs with drift enabled to validate thread lifecycle behavior.

## Reclamation and teardown

The shrinker evicts the lowest-STI linked atoms up to the requested object count. Removal marks the atom unlinked, deletes it with RCU-safe hash removal, decrements the global count, and drops the table’s reference. Readers holding a reference can finish safely. Module exit stops the scheduler, destroys the device node and character device, frees the registered shrinker, unlinks all remaining atoms, waits for RCU callbacks with `rcu_barrier`, and destroys the slab cache.

## Userspace ABI

The tester uses three ioctls:

| Ioctl | Function |
|---|---|
| `COG_LEARN` | Create a concept, relation, or sensorimotor metadata atom |
| `COG_THINK` | Read a UUID’s type, scores, and bounded name |
| `COG_FOCUS` | Increase STI with saturating fixed-point arithmetic |

The ABI is private to this experimental module and is not a FAISAL kernel ABI claim. A production interface would require a formal UAPI review, namespace/capability policy, compatibility guarantees, fuzzing, and a dedicated security review.
