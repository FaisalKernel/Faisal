# FAISAL Replication Protocol

## Scope

FAISAL replication transports journal state above the kernel. The transport must never turn model output into authority. Only a mutually authenticated replica identity, a monotonic term, a contiguous journal sequence, a valid hash-chain digest, and a quorum-approved commit may advance replicated state.

The wire contract is `faisal_replication.proto`. The repository now includes generated Python bindings and a bounded Python gRPC/TLS runtime in `faisal_replication_daemon.py`. Production deployments must provide mutually authenticated TLS certificates, trusted attestation and record-signature verifiers, durable storage, and an operational quorum configuration. The runtime refuses authority when those verification callbacks are not provisioned.

## Leader election

A replica requests a vote with its cluster ID, replica ID, term, last sequence, chain digest, attestation signature, key ID, and key generation. A voter grants at most one vote per term, and only when the candidate presents a valid attestation, is not behind the voter’s verified journal position, and has a trusted replica certificate. A future term causes the voter to advance its local term and revoke its current leadership; a stale term is denied.

An elected leader must renew a bounded lease through quorum acknowledgements. The lease is not authority by itself: every append still carries the leader term, previous digest, sequence, and signature. A partitioned leader cannot commit because it cannot obtain a quorum.

## Journal replication

`AppendEntries` carries contiguous records; `AppendJournal` remains a compatibility alias.
 A follower accepts records only when the leader term is current, the previous digest equals the follower’s chain tail, each sequence is exactly the next expected sequence, each record signature verifies against the provisioned key identity, and the leader identity is authenticated by the TLS client certificate. The follower acknowledges its match sequence only after durable write and `fsync`.

A commit is not authoritative because a leader merely sets `leader_commit`. When `leader_commit` is non-zero, `AppendEntries` must carry a `QuorumCertificate` whose cluster, leader, term, sequence, and digest match the proposed state. Each distinct vote must verify against the active trusted Ed25519 generation, and the certificate must contain a strict-majority number of votes. Invalid or under-quorum certificates fail closed before journal mutation.

`ReadCommit` returns only a quorum-committed term, sequence, and digest. A follower must not expose an uncommitted record as authoritative state. Snapshot installation uses the same signed identity and chain-root checks, and replaces state only after full digest verification.

## Partition behavior

The quorum rule is `quorum_size > replica_count / 2`. A two-versus-two partition in a four-replica cluster with a three-replica quorum cannot commit either side. When the partition heals, the side with the valid current term and matching chain digest can regain quorum; divergent state must be repaired through a verified append or signed snapshot, never by blind overwrite.

The live harness uses real TCP sockets with mutual TLS and inserts loopback `iptables` DROP rules after the TLS sessions are established. It verifies that traffic is interrupted and that a new authenticated session recovers after the rules are removed.

## External key providers

The remote provider interface supports AWS KMS asymmetric signing and HashiCorp Vault Transit signing. Credentials remain outside the repository: AWS uses the standard credential environment/role chain, while Vault requires an HTTPS address and explicitly supplied token. Key identity and generation are carried with the signed report and must match the verifier’s provisioned trust state.

The KMS client must enforce bounded request sizes, HTTPS, response key-identity matching, algorithm recording, and failure-closed behavior. AWS KMS requests use SigV4 and `kms:Sign`; Vault Transit responses must contain a versioned signature and key version.

## Hardware-backed key loading

`TPM2PublicKeyProvider` invokes `tpm2_readpublic` against an operator-provisioned object context and verifies the returned Ed25519 public-key SHA-256 digest. `SecureEnclavePublicKeyProvider` is an explicit vendor/TEE command boundary because Linux has no universal Secure Enclave API. Both providers fail closed when the executable, hardware, output format, or expected digest is unavailable or mismatched. A local software fixture is not physical hardware qualification.

## Live trust-key rotation

`KmsTrustKeyRotationController` polls a deployment-supplied KMS-backed proposal source and atomically activates exactly the next key generation after verifying authorization with the currently active Ed25519 key. Verification remains lock-protected during rotation; the previous generation is revoked immediately after activation, and malformed, stale, unauthorized, or unavailable proposals leave the active generation unchanged. The controller can run in the daemon lifecycle without restart and records the last rotation error for supervisory monitoring.

## Performance evidence

The controlled 10,000-record host benchmark at 256-byte payloads measured a median baseline chain-validation rate of approximately 812,637 records/second and a median Ed25519-verified rate of approximately 7,569 records/second, an observed incremental cost of approximately 130,888 ns per record in this Python implementation. This is a host microbenchmark, not a claim about network, KMS, TPM, secure-enclave, or production-cluster performance.

## Explicit non-claims

The bounded runtime implementation is not a claim of complete production distributed deployment. Live AWS/Vault credentials, physical TPM or secure-enclave evidence, production certificate rotation, large-scale fault injection, and hardware/provider qualification remain pending. The runtime deliberately requires external trusted verifiers and does not treat model output as authority.
