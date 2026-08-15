# CogOS FAISAL Kernel Module Security Review

## Scope

This review covers `cog_kernel.c`, the private ioctl tester, the module Makefile, and the QEMU harness. It is an experimental module review and does not certify the entire FAISAL kernel or the Linux kernel globally.

## Authority boundary

The module does not interpret model output, execute commands, access network resources, or grant capabilities. Its ioctls create and modify bounded metadata only. The module’s `COG_FOCUS` operation changes a fixed-point attention score; it cannot authorize a filesystem, network, device, browser, deployment, or kernel operation. This preserves FAISAL’s rule that model output is never equivalent to kernel authorization.

## Memory safety and concurrency

Atom allocation uses a dedicated slab cache and checks allocation failure. Names are copied with `strscpy` after forcing a bounded terminating NUL. User pointers are accessed only through `copy_from_user` and `copy_to_user`. All ioctl structures validate reserved fields, type ranges, UUID presence, and names before insertion.

The hash table is protected for mutation and mutable-field snapshots by `spin_lock_irqsave`. Read lookup uses RCU traversal and increments a `refcount_t` before leaving the RCU read-side critical section. Unlinking removes the atom from the hash table, marks it unavailable, decrements the global count, and drops the table reference. Final freeing occurs through `call_rcu`; module exit waits for callbacks with `rcu_barrier` before destroying the slab cache.

## Reclamation

The module uses the target kernel’s modern shrinker lifecycle: `shrinker_alloc`, callback registration, `shrinker_register`, and `shrinker_free`. The scan callback selects the lowest-STI linked atom under the same lock used for insertion and lookup snapshots. It reports the number of atom objects evicted, consistent with the object-oriented shrinker contract; it does not falsely report pages for metadata objects.

## Scheduler thread

The `cog_scheduler` thread sleeps for 10 ms between bounded attention updates and exits through `kthread_should_stop`. It is assigned FIFO priority because the attachment requested a high-priority stub, but the implementation performs only a short locked table walk and does not perform I/O, allocation, userspace access, or model execution. The module parameter `attention_drift=0` is used for deterministic validation; a separate QEMU run enables drift to validate the thread path.

A production design should not use global FIFO priority without workload measurements and admission controls. This module therefore remains experimental and private rather than being integrated into the production FAISAL ABI.

## Lifecycle and failure handling

Initialization unwinds in reverse order on every failure path. In particular, a failed shrinker allocation destroys the previously created slab cache. Character-device, class, device-node, scheduler, shrinker, atom, RCU, and cache teardown are all explicit. The tester validates module unload after active ioctl use.

## Validation performed

The module compiled against FAISAL’s Linux v7.2-rc7 build with `-Wall -Werror -Wno-declaration-after-statement`. QEMU validation passed with attention drift disabled and enabled. The executable tester validated learn, think, focus, post-focus state, malformed ioctl rejection, and clean unload. A targeted source scan found no `float` or `double` data types, unsafe copy/process primitives, or direct model-authority path.

## Remaining risks and non-claims

The global hash table and spinlock are intentionally a small experimental control plane, not a demonstrated high-scale AtomSpace. No KASAN, KCSAN, UBSAN, lockdep, syzkaller, randomized ioctl fuzzing, user-namespace isolation, capability policy, cgroup accounting, or physical-hardware validation is claimed here. The shrinker’s object eviction policy has not been benchmarked against production memory pressure. The FIFO scheduler priority has not been validated for system-wide latency or starvation. Those gaps are blockers for production integration.
