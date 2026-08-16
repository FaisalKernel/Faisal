# FAISAL M102 security review

## Security boundary

M102 is a userspace adapter supervised by the FAISAL M99 tool registry and M100 receipt model. It is not an authorization source. The model, command text, or external repository metadata cannot grant capability. A trusted registered tool supplies the executable implementation digest, and each invocation must already carry valid mission, task, authority-lease, registry-generation, and revocation-generation state.

## Threats and controls

| Threat | Control | Evidence and residual risk |
|---|---|---|
| Model-generated command abuse | Only a registered fixed executable and fixed argument vector are accepted; implementation digest is checked before launch | Selftest covers command provenance registration. Dynamic command construction is not supported. |
| Executable replacement | Command digest includes executable contents and `O_NOFOLLOW` file opening | The file can still change after the pre-launch digest and before `execve`; a future implementation should bind an opened executable file descriptor with `execveat` or supervisor-held immutable artifacts. |
| Network exfiltration | Private network namespace where available; seccomp default-kill policy omits socket and network syscalls; selftest attempts `socket(AF_INET, SOCK_STREAM, 0)` | The seccomp policy is architecture-specific to the tested x86_64 ABI. A future multi-architecture version requires architecture-specific audit and filter generation. |
| Filesystem write abuse | Landlock write restriction where available; fallback seccomp rejects writable `openat` flags; inherited descriptors above stderr are closed | The fallback cannot provide Landlock’s full path semantics. It is intentionally read-only for ordinary `openat` writes, but does not claim complete filesystem mediation for every future syscall or filesystem API. |
| Secret leakage through environment | Child calls `clearenv()` before execution and sets only a minimal PATH | Secrets accessible through already-open descriptors are reduced by descriptor closure, but a future supervisor should pass an explicit descriptor allowlist rather than a numeric close loop. |
| Scratch escape and traversal | Absolute scratch directory validation rejects `..`, requires a directory, and hashes device/inode metadata | The scope validator is deliberately conservative; symlink and mount-topology changes require continued Landlock or a stronger backend for complete containment. |
| Receipt forgery or crash ambiguity | Append-only journal records are SHA-256 protected, fdatasync is used, duplicate/conflict states are explicit, and ambiguous states never auto-retry | Journal durability depends on the host filesystem and storage stack. External tampering is detected, but cryptographic signatures and remote attestation are future work. |
| Corrupt replay | Header, record size, monotonic sequence, effect invariants, and digest are checked; any violation fails closed | Recovery does not infer successful effects after an incomplete commit. Operators must resolve ambiguity explicitly. |
| Tool revocation race | M99 tool state and revocation generation are checked immediately before the M102 receipt gate | A revocation occurring after the final check is represented by normal in-flight commit semantics and requires policy-level cancellation for stronger guarantees. |
| Output injection or oversized output | Capture is bounded at 4096 bytes and receipt text sanitizes non-printable bytes | The digest covers captured raw bytes; truncation returns verification failure. Semantic output verification remains outside M102. |

## Open-source integration risk

Engram, Mem0, and Letta were not imported because they are userspace memory or agent-runtime systems and cannot provide kernel authority or effect verification. OpenSandbox and sandbox-runtime were used as design references for runtime abstraction, default-deny egress, proxy boundaries, and credential separation; no external executable or dependency is trusted by M102. gVisor and Firecracker remain optional future backends and are not part of the current attack surface. Primary repository findings and URLs are preserved in `FAISAL-OPEN-SOURCE-REPOSITORY-RESEARCH.md`.

## Validation boundary

Strict compilation, static linking, host selftest, recovered-kernel QEMU, UBSan, and GCC analyzer passed. TSan and ASan+UBSan compiled, but their sanitizer runtimes were rejected by the production child seccomp policy before the complete selftest could run. This does not establish a race or memory defect, but it also does not constitute sanitizer runtime coverage. Sanitizer tests must be redesigned with a test-only policy or an out-of-process harness that does not place the instrumented runtime inside the restricted child.

## Conclusion

M102 provides a narrower and more auditable network-deny adapter than an unrestricted shell or generic model tool. It does not claim complete sandbox security, universal escape resistance, or support for arbitrary untrusted programs. The next security step is a policy compiler and independent verifier for controlled proxy egress, followed by optional gVisor/Firecracker backend validation.

## References

[1]: https://github.com/opensandbox-group/OpenSandbox — OpenSandbox primary repository.

[2]: https://github.com/anthropic-experimental/sandbox-runtime — Anthropic sandbox-runtime primary repository.

[3]: https://docs.kernel.org/userspace-api/landlock.html — Linux Landlock userspace API.

[4]: https://docs.kernel.org/userspace-api/seccomp_filter.html — Linux seccomp filter userspace API.

[5]: https://github.com/google/gvisor — gVisor primary repository.

[6]: https://github.com/firecracker-microvm/firecracker — Firecracker primary repository.
