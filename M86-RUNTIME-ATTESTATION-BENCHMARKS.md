# FAISAL M86 — Runtime Attestation Benchmarks

## M86 measurements

| Run | Exit | Elapsed |
|---:|---:|---:|
| 1 | 0 | 4953 ms |
| 2 | 0 | 4861 ms |
| 3 | 0 | 5155 ms |

Mean elapsed time was **4989.6 ms**, with a minimum of **4861 ms**, maximum of **5155 ms**, and range of **294 ms**. The measurement includes QEMU boot, initramfs setup, lifecycle-session creation, verifier registration, three ABI queries, digest computation, resampling, and guest shutdown.

## Functional evidence

The runtime-attestation selftest verified a verifier identity, nonzero capability handle, complete required observation mask `0x1f`, health mask `0x1f`, healthy state in the QEMU fixture, resource data, self-state data, resampling, and digest recomputation. The digest changed on resample because the sampled ABI state changed; this is expected evidence behavior, not a performance claim.

## Full-system audit

The final current-tree audit passed all 19 existing FAISAL QEMU harnesses. A clean out-of-tree kernel rebuild and fresh-image boot also passed. The CogOS harness was corrected to build its tester and module from source; the M73 selftest was rebuilt to eliminate a stale-binary audit artifact.

## Interpretation limits

These are functional QEMU harness measurements. They do not represent bare-metal latency, accelerator performance, remote attestation latency, cryptographic hardware throughput, production availability, or comparison against upstream Linux. Future benchmark work should separate ioctl latency, sampling latency, digest cost, and monitoring overhead from boot and shutdown time.
