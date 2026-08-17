# FAISAL Full TLS Replication Qualification

FAISAL distinguishes a **complete software replication fixture** from production distributed qualification. The fixture uses the actual Python gRPC daemon and generated protobuf bindings, three localhost replicas, distinct mutual-TLS certificates with `CN=replica-N`, trusted Ed25519 identities and record signatures, durable state files, and an authenticated strict-majority quorum certificate.

## Qualification command

Run the reproducible fixture from the repository root:

```sh
tools/faisal-replication/run_full_tls_replication_fixture.sh
```

The launcher writes `full-tls-replication-fixture.json` and the caller should create a detached signature with the operator-controlled qualification key. The signed report is checked with:

```sh
FAISAL_REPLICATION_EVIDENCE=/path/to/full-tls-replication-fixture.json \
FAISAL_PUBLIC_KEY=/path/to/trusted-qualification-public.pem \
FAISAL_EXPECTED_SOURCE_REV=$(git rev-parse HEAD) \
FAISAL_REPLICATION_VERIFY_REPORT=/path/to/replication-verification.tsv \
  python3 tools/faisal-build/verify_replication_qualification.py
```

The validator fails closed on stale or unsigned evidence, source mismatch, missing markers, absent quorum-certificate evidence, missing minority-partition denial, failed durable reload, or a missing explicit physical/production limitation.

## Safety property added in M171

`leader_commit` is no longer accepted as authority by itself. A non-zero commit requires a `QuorumCertificate` whose cluster, leader, term, sequence, and digest match the proposed state. Every distinct vote must verify against the active trusted Ed25519 key generation, and the certificate must contain a strict majority. Invalid or under-quorum certificates are rejected before journal mutation.

This preserves the core consensus boundary: a minority partition may continue to serve local transport requests, but it cannot produce an authoritative commit. The resulting `ReadCommit` state is durable and reloadable only after the certificate has passed verification.

## Covered cases

The M171 fixture validates mutual TLS and replica certificate identity, signed election, durable append and quorum commit, minority endpoint stop, majority-side progress, one-vote commit denial, partition healing and chain repair, tampered-record denial, under-quorum certificate denial, wrong client-certificate identity denial, untrusted certificate-authority denial, and durable reboot reload.

The existing live socket/iptables fixture remains a separate test. It validates loopback TLS stream interruption and reconnection, but it is not a substitute for the actual gRPC quorum fixture.

## Explicit limits

The fixture is software validation on one host with ephemeral test CA and Ed25519 keys. It is not independent multi-host qualification, production PKI qualification, production KMS/Vault qualification, physical TPM or secure-enclave evidence, or a claim of production-scale network behavior. Those remain separate release requirements. Model output is never authority.
