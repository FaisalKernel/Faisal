#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

TOOL = Path(__file__).with_name("faisal_release_authority.py")


def run(*args, expect=0):
    result = subprocess.run(
        ["python3", str(TOOL), *map(str, args)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != expect:
        raise AssertionError(
            f"expected rc={expect}, got rc={result.returncode}: {result.stdout}{result.stderr}"
        )
    return result


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    with tempfile.TemporaryDirectory(prefix="faisal-release-authority-test-") as temporary:
        root = Path(temporary)
        root_private = root / "root-private.pem"
        release_private = root / "release-private.pem"
        next_private = root / "next-private.pem"
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(root_private))
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(release_private))
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(next_private))
        for path in (root_private, release_private, next_private):
            os.chmod(path, 0o600)
        manifest = root / "FAISAL-build-manifest.json"
        sbom = root / "FAISAL-SBOM.spdx"
        checksums = root / "FAISAL-artifact-sha256sums.txt"
        manifest.write_text('{"schema":"org.faisal.build-manifest.v1","source_revision":"abc123","config_sha256":"def456"}\n')
        sbom.write_text("SPDXVersion: SPDX-2.3\n")
        checksums.write_text("artifact digest placeholder\n")
        keyring = root / "trusted-keyring.json"
        root_distribution = root / "trusted-root.json"
        run("create-keyring", "--root-private-key", root_private, "--release-private-key", release_private,
            "--keyring", keyring, "--root-distribution", root_distribution)
        approval = root / "approval.json"
        approval.write_text(json.dumps({
            "schema": "org.faisal.operator-approval.v1",
            "approved": True,
            "approval_id": "approval-test-001",
            "approved_by": "operator-test",
            "scope": "FAISAL-production-release",
            "expires_epoch": int(time.time()) + 3600,
        }) + "\n")
        attestation = root / "release-attestation.json"
        report = root / "verification.tsv"
        run("sign", "--release-private-key", release_private, "--keyring", keyring,
            "--operator-approval", approval, "--release-id", "test-release-001",
            "--manifest", manifest, "--sbom", sbom, "--checksums", checksums,
            "--attestation", attestation)
        run("verify", "--root-distribution", root_distribution, "--keyring", keyring,
            "--attestation", attestation, "--manifest", manifest, "--sbom", sbom,
            "--checksums", checksums, "--report", report)
        original_manifest = manifest.read_bytes()
        manifest.write_text(manifest.read_text() + "tamper\n")
        run("verify", "--root-distribution", root_distribution, "--keyring", keyring,
            "--attestation", attestation, "--manifest", manifest, "--sbom", sbom,
            "--checksums", checksums, "--report", report, expect=1)
        manifest.write_bytes(original_manifest)
        run("rotate-keyring", "--root-private-key", root_private, "--release-private-key", next_private,
            "--keyring", keyring, "--revoke-key-id", json.loads(keyring.read_text())["keys"][0]["key_id"])
        run("verify", "--root-distribution", root_distribution, "--keyring", keyring,
            "--attestation", attestation, "--manifest", manifest, "--sbom", sbom,
            "--checksums", checksums, "--report", report, expect=1)
        stale_approval = root / "stale-approval.json"
        stale_approval.write_text(json.dumps({
            "schema": "org.faisal.operator-approval.v1",
            "approved": True,
            "approval_id": "approval-stale",
            "approved_by": "operator-test",
            "scope": "FAISAL-production-release",
            "expires_epoch": int(time.time()) - 1,
        }) + "\n")
        run("sign", "--release-private-key", next_private, "--keyring", keyring,
            "--operator-approval", stale_approval, "--release-id", "stale-release",
            "--manifest", manifest, "--sbom", sbom, "--checksums", checksums,
            "--attestation", root / "stale-attestation.json", expect=1)
        unauthorized = root / "unauthorized.json"
        unauthorized.write_text(json.dumps({
            "schema": "org.faisal.operator-approval.v1",
            "approved": False,
            "approval_id": "approval-denied",
            "approved_by": "model-output",
            "scope": "FAISAL-production-release",
            "expires_epoch": int(time.time()) + 3600,
        }) + "\n")
        run("sign", "--release-private-key", next_private, "--keyring", keyring,
            "--operator-approval", unauthorized, "--release-id", "unauthorized-release",
            "--manifest", manifest, "--sbom", sbom, "--checksums", checksums,
            "--attestation", root / "unauthorized-attestation.json", expect=1)
        substituted_root = root / "substituted-root.json"
        substituted_root.write_text(root_distribution.read_text().replace(
            json.loads(root_distribution.read_text())["root_key_id"], "00000000000000000000000000000000"))
        run("verify", "--root-distribution", substituted_root, "--keyring", keyring,
            "--attestation", attestation, "--manifest", manifest, "--sbom", sbom,
            "--checksums", checksums, "--report", report, expect=1)
        print("FAISAL_RELEASE_AUTHORITY_SELFTEST_OK valid_tamper_revocation_stale_approval_unauthorized_root=pass")


if __name__ == "__main__":
    main()
