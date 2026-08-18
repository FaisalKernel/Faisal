#!/usr/bin/env python3
"""Validate signed external multi-host replication qualification evidence."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "org.faisal.external-replication-qualification.v1"
REQUIRED_MARKERS = {
    "EXTERNAL_HOSTS_DISTINCT_AND_NON_LOOPBACK_OK",
    "PRODUCTION_CA_CHAIN_AND_NODE_IDENTITY_OK",
    "CERTIFICATE_EXPIRY_REVOCATION_AND_ROTATION_OK",
    "LIVE_KMS_OR_VAULT_SIGN_VERIFY_OK",
    "KMS_OR_VAULT_KEY_ROTATION_AND_FAILURE_DENIAL_OK",
    "TPM_OR_SECURE_ENCLAVE_ATTESTATION_VERIFIED_OK",
    "EXTERNAL_MULTIHOST_GRPC_MTLS_OK",
    "LIVE_CROSS_HOST_PARTITION_INJECTED_OK",
    "MAJORITY_COMMIT_AND_MINORITY_DENIAL_EXTERNAL_OK",
    "CROSS_HOST_PARTITION_HEAL_AND_DURABLE_RECOVERY_OK",
    "DEPLOYMENT_RESTART_AND_ROLLBACK_EXTERNAL_OK",
}


def fail(message: str) -> None:
    raise ValueError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def valid_hex(value: object, length: int = 64) -> bool:
    return isinstance(value, str) and len(value) == length and value != "0" * length and all(c in "0123456789abcdef" for c in value.lower())


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON: {exc}")
    if not isinstance(value, dict):
        fail("JSON object required")
    return value


def verify_signature(public_key: Path, report: Path) -> None:
    signature = Path(f"{report}.sig")
    if not report.is_file() or not signature.is_file() or not public_key.is_file():
        fail("external replication report, detached signature, and public key are required")
    result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(report)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        fail("external replication evidence signature mismatch")


def verify(report: Path, public_key: Path, expected_revision: str, expected_package: Path | None, now: int, max_age: int) -> dict:
    if report.suffix != ".json":
        fail("structured JSON external replication evidence is required")
    verify_signature(public_key, report)
    data = load(report)
    if data.get("schema") != SCHEMA:
        fail("external replication schema mismatch")
    if data.get("status") != "external_multihost_production_qualified":
        fail("external replication evidence is not a completed production qualification")
    if data.get("source_revision") != expected_revision:
        fail("external replication source revision mismatch")
    reviewed = data.get("reviewed_epoch")
    if not isinstance(reviewed, int) or reviewed > now or now - reviewed > max_age:
        fail("external replication evidence is stale or timestamp is invalid")
    if data.get("model_output_is_authority") is not False:
        fail("model output cannot authorize replication qualification")
    if expected_package is not None:
        if not expected_package.is_file():
            fail("external replication handoff package manifest is missing")
        package = load(expected_package)
        package_ref = data.get("qualification_package")
        if not isinstance(package_ref, dict) or package_ref.get("manifest_sha256") != sha256_file(expected_package) or package_ref.get("package_id") != package.get("package_id"):
            fail("external replication evidence is not bound to the exact handoff package")
        if package.get("source_revision") != expected_revision:
            fail("external replication package source revision mismatch")
    candidate = data.get("candidate")
    if not isinstance(candidate, dict) or not valid_hex(candidate.get("protocol_sha256")) or not valid_hex(candidate.get("artifact_manifest_sha256")) or not candidate.get("build_id"):
        fail("exact replication candidate binding is incomplete")
    topology = data.get("topology")
    if not isinstance(topology, dict) or topology.get("node_count", 0) < 3 or topology.get("independent_hosts") is not True or topology.get("external_network") is not True:
        fail("independent external multi-host topology is required")
    nodes = topology.get("nodes")
    if not isinstance(nodes, list) or len(nodes) < 3:
        fail("at least three external replication nodes are required")
    node_ids = set()
    host_ids = set()
    for node in nodes:
        if not isinstance(node, dict) or not node.get("node_id") or not node.get("host_id") or not node.get("endpoint"):
            fail("external node identity is incomplete")
        if node["node_id"] in node_ids or node["host_id"] in host_ids:
            fail("replication nodes must have distinct node and host identities")
        if any(token in str(node["endpoint"]).lower() for token in ("127.0.0.1", "localhost", "::1")):
            fail("loopback endpoint cannot satisfy external multi-host qualification")
        if node.get("certificate_identity") != node["node_id"] or not node.get("certificate_serial") or node.get("certificate_not_after_epoch", 0) <= reviewed:
            fail("production node certificate identity or validity is incomplete")
        node_ids.add(node["node_id"])
        host_ids.add(node["host_id"])
    pki = data.get("production_pki")
    if not isinstance(pki, dict) or pki.get("live") is not True or not pki.get("ca_issuer") or not valid_hex(pki.get("trust_bundle_sha256")) or pki.get("revocation_check") is not True or pki.get("rotation_tested") is not True:
        fail("live production PKI lifecycle evidence is incomplete")
    kms = data.get("kms_or_vault")
    if not isinstance(kms, dict) or kms.get("live") is not True or kms.get("provider") not in {"aws_kms", "aws_kms_xks", "vault_transit", "external_hsm"} or not kms.get("key_id") or not kms.get("sign_verify_receipt") or kms.get("rotation_tested") is not True or kms.get("failure_denial_tested") is not True:
        fail("live KMS/Vault signing, rotation, and failure-denial evidence is incomplete")
    attestation = data.get("hardware_attestation")
    if not isinstance(attestation, dict) or attestation.get("live") is not True or attestation.get("provider") not in {"tpm2", "secure_enclave", "remote_attestation_service"} or not attestation.get("quote_verified") or not attestation.get("key_non_exportability_verified"):
        fail("live TPM/secure-enclave/remote-attestation evidence is incomplete")
    deployment = data.get("deployment")
    if not isinstance(deployment, dict) or not deployment.get("orchestrator") or deployment.get("restart_tested") is not True or deployment.get("rollback_tested") is not True or deployment.get("persistent_state_verified") is not True:
        fail("external deployment restart, rollback, and persistent-state evidence is incomplete")
    markers = set(data.get("markers", []))
    missing = sorted(REQUIRED_MARKERS - markers)
    if missing:
        fail("external replication markers missing: " + ",".join(missing))
    if data.get("quorum", {}).get("minority_commit_denied") is not True or data.get("quorum", {}).get("majority_commit_verified") is not True:
        fail("external quorum safety evidence is incomplete")
    limitations = data.get("limitations")
    if not isinstance(limitations, list) or any("pending" in str(item).lower() or "simulation" in str(item).lower() for item in limitations):
        fail("completed external production evidence cannot retain simulation or pending limitations")
    return data


def main() -> int:
    report = Path(os.environ.get("FAISAL_EXTERNAL_REPLICATION_EVIDENCE", ""))
    public_key = Path(os.environ.get("FAISAL_EXTERNAL_REPLICATION_PUBLIC_KEY", os.environ.get("FAISAL_PUBLIC_KEY", "")))
    expected = os.environ.get("FAISAL_EXPECTED_SOURCE_REV", "")
    package_value = os.environ.get("FAISAL_EXTERNAL_REPLICATION_PACKAGE", "")
    package = Path(package_value) if package_value else None
    output = Path(os.environ.get("FAISAL_EXTERNAL_REPLICATION_VERIFY_REPORT", f"{report}.verification.tsv"))
    try:
        data = verify(report, public_key, expected, package, int(os.environ.get("FAISAL_EXTERNAL_REPLICATION_NOW_EPOCH", str(int(time.time())))), int(os.environ.get("FAISAL_EXTERNAL_REPLICATION_MAX_AGE_SECONDS", str(30 * 24 * 3600))))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"check\tstatus\tdetail\nexternal_replication\tpass\t{data['topology']['node_count']}-node production qualification\n")
        print(f"FAISAL_EXTERNAL_REPLICATION_QUALIFICATION_OK report={output}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"check\tstatus\tdetail\nexternal_replication\tblocked\t{exc}\n")
        print(f"FAISAL_EXTERNAL_REPLICATION_QUALIFICATION_BLOCKED reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
