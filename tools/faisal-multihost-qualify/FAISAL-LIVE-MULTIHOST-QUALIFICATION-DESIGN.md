# FAISAL Live Multihost Qualification Evidence

## Purpose

FAISAL must qualify distributed autonomous workloads on real reachable nodes, not infer cluster behavior from a local process, loopback socket, QEMU single-host fixture, or model output. This subsystem prepares and validates the evidence contract required for a real live-multihost qualification while keeping the production gate fail-closed.

## Required live environment

A production qualification requires at least three independently identified nodes, a declared topology, a declared transport, a quorum policy, synchronized or explicitly bounded clocks, exact kernel and artifact binding on every node, authenticated node and transport identity, and externally attributable cluster evidence. A single host or local loopback is never a multihost result.

## Realistic workload pack

The required workload pack covers agent coordination, distributed inference, checkpoint recovery, and migration rollback. Each workload must provide a reproducible trace, output digest, resource and transport observations, checkpoint/recovery evidence, and final disposition. The workload pack is evaluated together with the exact release, node topology, network transport, and runtime versions.

## Fault and recovery pack

The required fault pack covers node loss, network partition, transport reconnect, and workload restart. A passing result requires a well-defined recovery outcome, preserved integrity, bounded recovery time, and an attributable trace. Migration and rollback must demonstrate source/destination identity, state/checkpoint integrity, capability preservation, and safe rollback under failure.

## Structural versus live qualification

The three-node fixture in `faisal_multihost_qualify.py` validates schema, quorum, workload, fault, binding, replay, and authority behavior only. It does not create nodes, open external transport, execute a distributed workload, attest node identity, or perform migration. The local single-host probe is recorded as a blocker. Only `live_external` evidence with independently verified nodes, transport, workload execution, and fault/recovery results can satisfy the live-multihost blocker.

## Authority boundary

The contract never treats model output, node claims, transport receipts, provider metadata, or synthetic fixtures as production authority. It never issues production approval. Real qualification requires external infrastructure, independently verifiable evidence, and authorized release governance.
