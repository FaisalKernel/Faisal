# Seccomp primary-source findings

Accessed 2026-08-17. Primary sources: [Linux Seccomp BPF documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html) and [seccomp(2) manual](https://www.kernel.org/doc/man-pages/online/pages/man2/seccomp.2.html).

The kernel documentation states that filters operate on `struct seccomp_data`, including syscall number and `arch`; architecture must be checked before syscall numbers. `PR_SET_NO_NEW_PRIVS` or `CAP_SYS_ADMIN` is required before installing a filter. `execve` preserves filters across exec, and `SECCOMP_RET_KILL_PROCESS` terminates with `SIGSYS`. `SECCOMP_RET_TRAP` delivers `SIGSYS` with `si_syscall` and `si_arch`, while `SECCOMP_RET_LOG` can be used during development to identify required syscalls. Seccomp is not a complete sandbox and should be combined with an LSM such as Landlock and other isolation controls.

Implementation implication: the unresolved QEMU failure must be diagnosed using the guest-reported `si_syscall`/`si_arch` or a development `SECCOMP_RET_LOG` policy, while retaining an architecture-checked, deny-by-default production filter. The trusted launcher must not claim acceptance until the required filter passes in QEMU.
