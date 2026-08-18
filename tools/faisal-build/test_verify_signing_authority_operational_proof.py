#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import faisal_release_authority as authority
import verify_signing_authority_operational_proof as validator

TOOL = Path(__file__).with_name("faisal_release_authority.py")
EXPECTED_REVISION = "abc123"


def run(*args, expect=0):
    result = subprocess.run(["python3", str(TOOL), *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != expect:
        raise AssertionError(f"expected rc={expect}, got {result.returncode}: {result.stdout}{result.stderr}")
    return result


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write_approval(path: Path, approval_id: str) -> None:
    path.write_text(json.dumps({
        "schema": "org.faisal.operator-approval.v1",
        "approved": True,
        "approval_id": approval_id,
        "approved_by": "operator-alpha",
        "scope": "FAISAL-production-release",
        "expires_epoch": int(time.time()) + 3600,
    }) + "\n")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="faisal-signing-operational-") as raw:
        root = Path(raw)
        root_private = root / "root-private.pem"
        release_private = root / "release-private.pem"
        next_private = root / "next-private.pem"
        for path in (root_private, release_private, next_private):
            openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(path))
            os.chmod(path, 0o600)
        manifest = root / "manifest.json"
        sbom = root / "sbom.spdx"
        checksums = root / "checksums.txt"
        manifest.write_text(json.dumps({"source_revision": EXPECTED_REVISION}) + "\n")
        sbom.write_text("SPDXVersion: SPDX-2.3\n")
        checksums.write_text("artifact sha256\n")
        keyring = root / "trusted-keyring.json"
        root_distribution = root / "trusted-root.json"
        run("create-keyring", "--root-private-key", root_private, "--release-private-key", release_private, "--keyring", keyring, "--root-distribution", root_distribution, "--not-before", int(time.time()) - 60, "--not-after", int(time.time()) + 3600)
        approval = root / "approval.json"
        write_approval(approval, "approval-one")
        attestation_one = root / "attestation-one.json"
        run("sign", "--release-private-key", release_private, "--keyring", keyring, "--operator-approval", approval, "--release-id", "release-one", "--manifest", manifest, "--sbom", sbom, "--checksums", checksums, "--attestation", attestation_one)
        old_key_id = json.loads(keyring.read_text())["keys"][0]["key_id"]
        run("rotate-keyring", "--root-private-key", root_private, "--release-private-key", next_private, "--keyring", keyring, "--revoke-key-id", old_key_id, "--not-before", int(time.time()) - 60, "--not-after", int(time.time()) + 3600)
        approval_two = root / "approval-two.json"
        write_approval(approval_two, "approval-two")
        attestation_two = root / "attestation-two.json"
        run("sign", "--release-private-key", next_private, "--keyring", keyring, "--operator-approval", approval_two, "--release-id", "release-two", "--manifest", manifest, "--sbom", sbom, "--checksums", checksums, "--attestation", attestation_two)
        run("verify", "--root-distribution", root_distribution, "--keyring", keyring, "--attestation", attestation_two, "--manifest", manifest, "--sbom", sbom, "--checksums", checksums, "--report", root / "release-two.tsv")
        run("verify", "--root-distribution", root_distribution, "--keyring", keyring, "--attestation", attestation_one, "--manifest", manifest, "--sbom", sbom, "--checksums", checksums, "--report", root / "old-key.tsv", expect=1)

        keyring_data = json.loads(keyring.read_text())
        new_key_id = next(key["key_id"] for key in keyring_data["keys"] if key["key_id"] != old_key_id)
        proof = {
            "schema": validator.SCHEMA,
            "evidence_class": "operator_ceremony",
            "status": "operationally_proven",
            "generated_epoch": int(time.time()),
            "model_output_is_not_authority": True,
            "root_distribution_sha256": authority.sha256_file(root_distribution),
            "keyring_sha256": authority.sha256_file(keyring),
            "root_key_id": json.loads(root_distribution.read_text())["root_key_id"],
            "protected_root": {
                "storage_class": "air_gapped_offline",
                "offline": True,
                "private_key_exported": False,
                "recovery_tested": True,
                "operator_witnesses": [
                    {"operator_id": "operator-alpha", "role": "ceremony-lead", "acknowledged": True},
                    {"operator_id": "operator-beta", "role": "independent-witness", "acknowledged": True},
                ],
            },
            "trusted_distribution": {
                "root_distribution_sha256": authority.sha256_file(root_distribution),
                "channels": ["offline-media-dual-control", "protected-registry-replica"],
                "verification_receipts": [
                    {"recipient_id": "release-site-a", "verified": True, "root_distribution_sha256": authority.sha256_file(root_distribution), "keyring_sha256": authority.sha256_file(keyring)},
                    {"recipient_id": "release-site-b", "verified": True, "root_distribution_sha256": authority.sha256_file(root_distribution), "keyring_sha256": authority.sha256_file(keyring)},
                ],
            },
            "rotation": {
                "tested": True,
                "operator_approved": True,
                "events": [{"event_id": "rotation-one", "old_key_id": old_key_id, "new_key_id": new_key_id, "revocation_confirmed": True}],
            },
            "revocation": {"tested": True, "rejection_evidence": ["old-key-attestation-rejected-after-rotation", "new-key-recovery-attestation-verified"]},
            "release_binding": {"source_revision": EXPECTED_REVISION, "release_id": "release-two", "attestation_sha256": authority.sha256_file(attestation_two)},
        }
        proof_path = root / "operational-proof.json"
        proof_path.write_bytes(authority.canonical(proof))
        proof_path.with_name(proof_path.name + ".sig").write_bytes(authority.sign_bytes(root_private, authority.canonical(proof)))
        validator.verify(proof_path, root_distribution, keyring, EXPECTED_REVISION, int(time.time()), 3600)

        tampered = copy.deepcopy(proof)
        tampered["trusted_distribution"]["channels"] = ["one-channel-only"]
        proof_path.write_bytes(authority.canonical(tampered))
        try:
            validator.verify(proof_path, root_distribution, keyring, EXPECTED_REVISION, int(time.time()), 3600)
        except ValueError:
            pass
        else:
            raise AssertionError("tampered operational proof accepted")
    print("FAISAL_SIGNING_AUTHORITY_OPERATIONAL_PROOF_TEST_OK ceremony_distribution_rotation_revocation_recovery_tamper_denied_simulation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
