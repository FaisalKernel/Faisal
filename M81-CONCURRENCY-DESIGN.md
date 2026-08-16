# M81 Concurrent Lifecycle and IPC Design

## Objective

M81 validates the existing FAISAL lifecycle and IPC primitives under simultaneous session activity. The test deliberately stays above the kernel’s existing ABI rather than adding a second concurrency API. This preserves the Linux-derived boundary: the kernel enforces session lineage, agent identity, capability handles, queue ownership, cancellation, and locking; the userspace service supplies workload structure and the test oracle.

## Workload Model

Each of eight pthread workers opens its own lifecycle device session. Within that session it creates a planner source light-agent and a verifier child light-agent. The worker creates one bounded IPC channel with a queue depth of 32. A second pthread attaches to the same session and selects the verifier endpoint as the consumer. The producer and consumer synchronize with a barrier before live traffic begins.

The producer first submits 64 malformed IPC requests and requires `EINVAL` for every request. It then submits a valid request with a mutated sender capability and requires `EACCES`. It queues twelve valid messages and cancels every other message, requiring `-ECANCELED` status for six cancellations. Finally, it sends 96 messages with nonblocking retry on `EAGAIN` while the consumer receives concurrently with a bounded timeout. Queue pressure is counted rather than treated as an error.

Structured valid messages use a per-worker xorshift32 state seeded from the worker index. The generator varies priority, type, schema, payload length, and payload bytes within the ABI bounds. The expected count is 872 valid generated messages per eight-worker run: one capability test, twelve cancellation messages, and 96 live messages per worker.

## Synchronization and Lifetime

The service uses C11 atomics for the producer-completion flag and consumer result, a pthread barrier for the start gate, and `pthread_join` before channel close and descriptor close. The kernel’s channel operations are invoked concurrently through the same session descriptor only where the ABI permits it: send and receive dispatch paths release the ioctl mutex and protect queue state internally. The test does not close or revoke a channel while a receive is active.

On any setup or operation failure, the worker records a failure and closes the channel where possible. A failed worker cannot authorize another worker or alter another session because every worker owns a separate file descriptor and session lineage.

## Failure Injection

Failure injection is structured rather than memory-corrupting. Invalid sizes exercise UAPI validation; sender and channel capability mutations exercise authorization denial; cancellation removes queued messages; queue depth and nonblocking send exercise backpressure. The test does not deliberately trigger kernel memory corruption or use undocumented ioctl values.

## Verification Boundary

The test proves observed behavior for the exercised paths and configurations. It does not prove absence of all races or deadlocks, does not model hardware DMA, and does not establish that a model, planner, or natural-language output is trustworthy. Those claims remain outside the kernel test’s scope.
