# M83 Persistence Research Notes

## Sources consulted

The Linux man-pages documentation states that `fsync()` flushes modified file data and metadata so the data can be retrieved after a crash or reboot, while `fdatasync()` flushes file data and only metadata required for subsequent retrieval. It also explicitly warns that synchronizing a file does not necessarily synchronize the containing directory entry; a directory file descriptor must be synchronized when directory persistence is required [1]. M83 therefore uses `fdatasync()` for journal and manifest contents, keeps fixed paths rather than relying on rename-based directory-entry atomicity, and documents that this userspace protocol is not a filesystem transaction.

The Linux VFS documentation describes VFS system calls as process-context operations and explains that filesystem locking is a separate concern managed by the filesystem and VFS implementation [2]. M83 remains a userspace service protocol over ordinary files and the existing FAISAL memory ioctl. It does not claim to replace VFS transactions or provide a kernel-wide persistent-memory transaction primitive.

## Implementation impact

M83 writes a prepared coordinator manifest, copies each pre-transaction journal to a durable backup, applies each operation through the existing capability-scoped FAISAL persistent-memory service, and marks the manifest committed only after all operations complete. If the process is interrupted after a partial apply, recovery restores every journal from its backup and marks the manifest aborted. Successful transactions delete backups after the committed manifest is durable.

This is a bounded two-journal userspace transaction protocol. It provides tested rollback behavior for the exercised failure point, but it cannot make the kernel memory records and all filesystem metadata a single hardware-atomic transaction. A production implementation would need a stronger durable transaction substrate, directory synchronization where path replacement is used, power-loss testing, and broader filesystem coverage.

## References

[1]: https://man7.org/linux/man-pages/man2/fsync.2.html "fsync(2) — synchronize a file's in-core state with storage device"
[2]: https://docs.kernel.org/filesystems/vfs.html "Overview of the Linux Virtual File System"
