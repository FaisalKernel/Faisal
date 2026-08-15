
## Additional findings

The seccomp interface filters system calls and arguments with classic BPF, can be inherited across fork/clone and preserved across execve, and can be synchronized across threads. It can log non-allow actions and supports user notifications, but it filters syscall behavior rather than tensor objects, model outputs, or semantic subgraphs. FAISAL should use seccomp as a complementary tool-service sandbox, not as the tensor-capability primitive.

Linux credentials distinguish objects, ownership, objective context, subjects, subjective context, actions, and DAC/MAC rules. Tasks and files are subjects/objects in the existing access calculation, while UID/GID and LSM labels remain relevant. FAISAL agent identity should be an additional kernel-held attribution dimension bound to the existing task credentials and lineage, not a replacement for Linux credentials or LSM enforcement.

Source URLs:
- https://man7.org/linux/man-pages/man2/seccomp.2.html
- https://docs.kernel.org/security/credentials.html
