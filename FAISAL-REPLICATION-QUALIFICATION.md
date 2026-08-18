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

## M178 external qualification handoff

M171 software-fixture evidence must not be reused as production evidence. Prepare the external handoff package from the exact candidate source revision:

```sh
python3 tools/faisal-build/prepare_external_replication_qualification_bundle.py \
  --source-dir /home/ubuntu/agi-kernel/linux \
  --source-revision <exact-candidate-source-revision> \
  --software-evidence /path/to/m171-full-tls-replication-qualification-validation.json \
  --output-dir /path/to/m178-external-replication
```

An authorized external operator must execute the package on at least three independent hosts using non-loopback network endpoints. Evidence must bind each node identity to its production CA certificate, record expiry, revocation and rotation, and include live cross-host partition, quorum, heal, durable restart, and rollback results. It must also include live AWS KMS/XKS or Vault Transit sign/verify receipts, key rotation and failure-denial evidence, and a TPM2, secure-enclave, or approved remote-attestation quote proving non-exportable key custody. A local Vault dev server, loopback iptables test, self-signed CA, generated test key, or software-only attestation is not production evidence.

Validate completed evidence with:

```sh
FAISAL_EXTERNAL_REPLICATION_EVIDENCE=/path/to/external-replication-qualification.json \
FAISAL_EXTERNAL_REPLICATION_PUBLIC_KEY=/path/to/trusted-production-validation-key.pem \
FAISAL_EXTERNAL_REPLICATION_PACKAGE=/path/to/qualification-package.json \
FAISAL_EXPECTED_SOURCE_REV=<exact-candidate-source-revision> \
FAISAL_EXTERNAL_REPLICATION_VERIFY_REPORT=/path/to/external-replication-verification.tsv \
  python3 tools/faisal-build/verify_external_replication_qualification.py
```

The validator fails closed on loopback or duplicate hosts, missing production PKI lifecycle evidence, absent live KMS/Vault receipts, missing hardware-backed attestation, incomplete deployment recovery, stale or unsigned evidence, package/source mismatch, missing quorum markers, or any remaining simulation/pending limitation.

## Explicit limits

The fixture is software validation on one host with ephemeral test CA and Ed25519 keys. It is not independent multi-host qualification, production PKI qualification, production KMS/Vault qualification, physical TPM or secure-enclave evidence, or a claim of production-scale network behavior. M178 creates the external handoff and validator but cannot supply real hosts, production credentials, hardware roots, or operator witnesses from this sandbox. Those remain release requirements. Model output is never authority.
