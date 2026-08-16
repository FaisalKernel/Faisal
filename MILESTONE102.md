# FAISAL M102: Network-Isolated Nondeterministic Tool Adapter

## Status

M102 is implemented and in validation. It is a userspace FAISAL system-service primitive, not a new kernel syscall and not an imported agent framework. The implementation adapts verified isolation ideas from OpenSandbox and Anthropic’s sandbox-runtime while retaining FAISAL’s M99 authority and M100 effect-receipt boundary. The reviewed repositories are recorded in `FAISAL-OPEN-SOURCE-REPOSITORY-RESEARCH.md` and the selection rationale is recorded in `M102-OPEN-SOURCE-INTEGRATION-DESIGN.md`.

## What is implemented

The adapter accepts a fixed executable and fixed argument vector that are registered as a tool implementation. Before execution, it validates the M99 invocation, tool registration state, revocation generation, invocation input digest, and executable implementation digest. The command digest binds the absolute executable path, arguments, and SHA-256 digest of the executable contents. A model response alone cannot create or alter this authority.

The child process clears inherited environment variables, enters an unprivileged user/network namespace when supported, applies Landlock write-scope restriction when supported, closes inherited descriptors, and installs a default-kill seccomp filter. The filter denies socket and network syscalls and rejects writable `openat` flag combinations. When the running kernel lacks the required namespace or Landlock capability, the adapter degrades only to the explicitly tested seccomp-only network-deny/read-only-open policy; it never silently permits unrestricted network or filesystem writes.

The service records pending, effected, committed, failed, and ambiguous durable receipts. Results are bounded and sanitized for receipt storage, while the output digest covers the captured bytes. Duplicate idempotency keys return the prior committed result, conflicting input returns conflict, and ambiguous or effected states are never automatically retried. Corrupt journal replay fails closed.

## Validation

The final source passed strict userspace compilation, static linking, host selftest, recovered-kernel QEMU, UBSan, and GCC analyzer. TSan and ASan+UBSan binaries compiled, but their runtimes were rejected inside the production deny-by-default child policy; this is recorded as a sanitizer-environment limitation rather than a pass. The existing M100 host and QEMU regressions also passed after M102 was added.

The real-kernel QEMU harness booted FAISAL, discovered `/dev/agi_lifecycle`, required kernel authority, verified a committed fixed-program effect, checked idempotency and conflict, denied a socket attempt, denied a writable file attempt, rejected traversal, replayed committed and failed states, and rejected a corrupted journal.

## Explicit non-claims

M102 is not a general network proxy, browser adapter, microVM, gVisor runtime, or complete nondeterministic tool ecosystem. Network access is deny-by-default; controlled proxy egress, browser interaction, remote credential injection, and backend selection remain future work. The measured host benchmark is an end-to-end service selftest timing, not a comparison against another runtime or a physical-hardware performance claim. No claim of universal kernel or sandbox superiority is made.

## References

[1]: https://github.com/opensandbox-group/OpenSandbox — OpenSandbox sandbox protocol, runtime, network policy, credential vault, and image-verification reference.

[2]: https://github.com/anthropic-experimental/sandbox-runtime — Anthropic sandbox-runtime filesystem, network, and Unix-socket restriction reference.

[3]: https://github.com/google/gvisor — gVisor userspace application-kernel isolation reference.

[4]: https://github.com/firecracker-microvm/firecracker — Firecracker microVM isolation reference.

[5]: https://docs.kernel.org/userspace-api/landlock.html — Linux Landlock userspace API documentation.
