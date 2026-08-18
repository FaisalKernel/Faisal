#!/usr/bin/env python3
"""Validate operational proof for the FAISAL production signing authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "org.faisal.signing-authority-operational-proof.v1"
ALLOWED_ROOT_STORAGE = {"offline_hsm", "air_gapped_offline", "offline_mpc"}


def fail(message: str) -> None:
    raise ValueError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON: {exc}")
    if not isinstance(value, dict):
        fail("JSON object required")
    return value


def valid_hex(value: object, length: int = 64) -> bool:
    return isinstance(value, str) and len(value) == length and value != "0" * length and all(c in "0123456789abcdef" for c in value.lower())


def public_key_id(pem: str) -> str:
    try:
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-inform", "PEM", "-outform", "DER"],
            input=pem.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"invalid root public key: {exc}")
    return hashlib.sha256(result.stdout).hexdigest()[:32]


def verify_signature(public_pem: str, signature: Path, report: Path, payload: bytes) -> None:
    import tempfile
    with tempfile.TemporaryDirectory(prefix="faisal-signing-proof-") as directory:
        root = Path(directory)
        pub = root / "root.pem"
        sig = root / "proof.sig"
        body = root / "proof.json"
        pub.write_text(public_pem)
        sig.write_bytes(signature.read_bytes())
        body.write_bytes(payload)
        try:
            subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), str(body)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except (OSError, subprocess.CalledProcessError):
            fail("operational-proof root signature mismatch")


def verify(proof: Path, root_distribution: Path, keyring: Path, expected_source_revision: str, now: int, max_age: int) -> dict:
    if proof.suffix != ".json" or not proof.is_file() or not Path(f"{proof}.sig").is_file():
        fail("operational proof JSON and detached signature are required")
    if not root_distribution.is_file() or not keyring.is_file():
        fail("trusted root distribution and keyring are required")
    root = load(root_distribution)
    data = load(proof)
    if root.get("schema") != "org.faisal.trusted-root.v1":
        fail("trusted root schema mismatch")
    if data.get("schema") != SCHEMA:
        fail("operational-proof schema mismatch")
    if data.get("evidence_class") != "operator_ceremony" or data.get("status") != "operationally_proven":
        fail("operational proof is not a completed operator ceremony")
    if data.get("model_output_is_not_authority") is not True:
        fail("model output cannot authorize signing authority")
    generated = data.get("generated_epoch")
    if not isinstance(generated, int) or generated > now or now - generated > max_age:
        fail("operational proof is stale or timestamp is invalid")
    root_pem = root.get("public_key_pem")
    if not isinstance(root_pem, str) or public_key_id(root_pem) != root.get("root_key_id"):
        fail("trusted root identity is invalid")
    verify_signature(root_pem, Path(f"{proof}.sig"), proof, canonical(data))
    if data.get("root_distribution_sha256") != sha256_file(root_distribution):
        fail("root distribution digest mismatch")
    if data.get("keyring_sha256") != sha256_file(keyring):
        fail("keyring digest mismatch")
    if data.get("root_key_id") != root.get("root_key_id"):
        fail("operational proof root binding mismatch")
    custody = data.get("protected_root")
    if not isinstance(custody, dict) or custody.get("storage_class") not in ALLOWED_ROOT_STORAGE:
        fail("protected root must use an offline HSM, air-gapped offline, or offline MPC custody class")
    if custody.get("private_key_exported") is not False or custody.get("offline") is not True or custody.get("recovery_tested") is not True:
        fail("protected-root custody controls are incomplete")
    witnesses = custody.get("operator_witnesses")
    if not isinstance(witnesses, list) or len(witnesses) < 2:
        fail("at least two operator witnesses are required")
    witness_ids = set()
    for witness in witnesses:
        if not isinstance(witness, dict) or not witness.get("operator_id") or witness.get("operator_id") in witness_ids:
            fail("operator witness identity is incomplete or duplicated")
        if witness.get("operator_id") in {"model-output", "FAISAL-model", "self"} or witness.get("acknowledged") is not True or not witness.get("role"):
            fail("operator witness acknowledgement is invalid")
        witness_ids.add(witness["operator_id"])
    distribution = data.get("trusted_distribution")
    if not isinstance(distribution, dict) or distribution.get("root_distribution_sha256") != sha256_file(root_distribution):
        fail("trusted distribution is not bound to the root distribution")
    channels = distribution.get("channels")
    receipts = distribution.get("verification_receipts")
    if not isinstance(channels, list) or len(set(channels)) < 2 or not isinstance(receipts, list) or len(receipts) < 2:
        fail("at least two trusted distribution channels and two verification receipts are required")
    recipients = set()
    for receipt in receipts:
        if not isinstance(receipt, dict) or not receipt.get("recipient_id") or receipt.get("recipient_id") in recipients or receipt.get("verified") is not True:
            fail("trusted distribution receipt is incomplete")
        if receipt.get("root_distribution_sha256") != sha256_file(root_distribution) or receipt.get("keyring_sha256") != sha256_file(keyring):
            fail("trusted distribution receipt digest mismatch")
        recipients.add(receipt["recipient_id"])
    rotation = data.get("rotation")
    if not isinstance(rotation, dict) or rotation.get("tested") is not True or rotation.get("operator_approved") is not True:
        fail("key rotation proof is incomplete")
    events = rotation.get("events")
    if not isinstance(events, list) or not events:
        fail("key rotation event history is required")
    for event in events:
        if not isinstance(event, dict) or not event.get("event_id") or not event.get("old_key_id") or not event.get("new_key_id") or event.get("old_key_id") == event.get("new_key_id") or event.get("revocation_confirmed") is not True:
            fail("key rotation event is incomplete")
    revocation = data.get("revocation")
    if not isinstance(revocation, dict) or revocation.get("tested") is not True or not revocation.get("rejection_evidence"):
        fail("revocation and rejected-old-key evidence are required")
    release = data.get("release_binding")
    if not isinstance(release, dict) or release.get("source_revision") != expected_source_revision or not valid_hex(release.get("attestation_sha256")) or not release.get("release_id"):
        fail("operational proof is not bound to the expected release")
    serialized = proof.read_text()
    if "BEGIN PRIVATE KEY" in serialized or "BEGIN RSA PRIVATE KEY" in serialized or "private_key_pem" in serialized:
        fail("private key material must never appear in operational proof")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--root-distribution", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-age", type=int, default=30 * 24 * 3600)
    args = parser.parse_args()
    try:
        verify(args.proof, args.root_distribution, args.keyring, args.expected_source_revision, int(time.time()), args.max_age)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text("check\tstatus\tdetail\noperational_signing_authority\tpass\toperator_ceremony_root_distribution_rotation_revocation\n")
        print(f"FAISAL_SIGNING_AUTHORITY_OPERATIONAL_PROOF_OK report={args.report}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(f"check\tstatus\tdetail\noperational_signing_authority\tblocked\t{exc}\n")
        print(f"FAISAL_SIGNING_AUTHORITY_OPERATIONAL_PROOF_BLOCKED reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
