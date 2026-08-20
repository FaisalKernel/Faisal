# FAISAL research note — agent capability revocation freshness

**Research date:** 2026-08-20. **Decision scope:** a deterministic userspace control-plane validator that applies a caller-supplied revocation snapshot to local agent capability receipts. This is not an identity-provider client, token-revocation endpoint, signature verifier, distributed stream implementation, or production authorization system.

## Primary-source observations

RFC 7009 defines a revocation endpoint through which an authorization server can invalidate a refresh token and, depending on server policy, may also invalidate related access tokens or the associated grant. The standard requires refresh-token revocation support and recommends access-token revocation support. [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)

The SPIFFE Workload API uses server-side streams to propagate identity-related updates such as revocations, credential rotation, and CA changes. Each response carries the complete current set rather than a delta; clients must treat absent material as redacted, discard prior values not present in a complete update, and reconnect promptly after a stream termination. [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)

## Bounded implementation direction

Implement a provider-neutral **agent capability revocation snapshot** with a monotonically increasing epoch, issue time, bounded freshness deadline, and complete set of revoked receipt digests. The presentation validator should bind an existing local possession receipt digest to the snapshot epoch and deny stale snapshots, regressed epochs, incomplete/non-complete snapshots, revoked receipts, missing receipt membership, and authority-boundary violations. It should emit a deterministic non-authoritative local decision record.

The contract will not poll or subscribe to any external source, prove stream delivery, authenticate a revocation issuer, distribute revocations between hosts, revoke external credentials, alter kernel policy, execute tools, or promote a snapshot/receipt/model/provider claim into execution or production authority.
