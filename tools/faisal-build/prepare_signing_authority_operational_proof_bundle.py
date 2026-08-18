#!/usr/bin/env python3
"""Prepare a public, operator-controlled signing-authority proof package."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

SCHEMA = "org.faisal.signing-authority-operational-proof-package.v1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def copy(src: Path, root: Path, name: str) -> dict:
    if not src.is_file():
        raise SystemExit(f"missing signing-authority input: {src}")
    dst = root / name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return {"path": name, "sha256": sha256(src), "bytes": src.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--root-distribution", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--keyring-signature", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    source = args.source_dir.resolve()
    output = args.output_dir.resolve()
    root = output / f"faisal-signing-authority-{args.source_revision[:12]}"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    files = {
        "trusted_root_distribution": copy(args.root_distribution, root, "trust/trusted-root.json"),
        "trusted_keyring": copy(args.keyring, root, "trust/trusted-keyring.json"),
        "trusted_keyring_signature": copy(args.keyring_signature, root, "trust/trusted-keyring.json.sig"),
        "release_attestation": copy(args.attestation, root, "release/release-attestation.json"),
        "release_authority": copy(source / "tools/faisal-build/faisal_release_authority.py", root, "controls/faisal_release_authority.py"),
        "authority_selftest": copy(source / "tools/faisal-build/test_faisal_release_authority.py", root, "controls/test_faisal_release_authority.py"),
        "operational_validator": copy(source / "tools/faisal-build/verify_signing_authority_operational_proof.py", root, "controls/verify_signing_authority_operational_proof.py"),
        "runbook": copy(source / "FAISAL-SIGNING-AUTHORITY.md", root, "runbook/FAISAL-SIGNING-AUTHORITY.md"),
        "program_state": copy(source / "FAISAL-PROGRAM-STATE.json", root, "project/FAISAL-PROGRAM-STATE.json"),
    }
    package_id = f"faisal-signing-authority-{args.source_revision[:12]}"
    manifest = {
        "schema": SCHEMA,
        "package_id": package_id,
        "generated_epoch": int(time.time()),
        "status": "operator_ceremony_required",
        "source_revision": args.source_revision,
        "files": files,
        "operational_contract": {
            "root_storage_classes": ["offline_hsm", "air_gapped_offline", "offline_mpc"],
            "minimum_operator_witnesses": 2,
            "distribution_channels": 2,
            "required_events": ["root_ceremony", "trusted_distribution", "release_signing", "key_rotation", "key_revocation", "recovery_test"],
            "private_keys_in_package": False,
            "model_output_is_not_authority": True,
        },
        "limitations": [
            "This package is public handoff material and not proof that a human ceremony occurred.",
            "The sandbox cannot prove offline HSM or air-gapped custody, independent operator witnesses, or production distribution receipt.",
            "The operational-proof template is intentionally rejected until completed and signed by operators using the root key.",
        ],
    }
    manifest_path = root / "operational-proof-package.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    template = {
        "schema": "org.faisal.signing-authority-operational-proof.v1",
        "evidence_class": "operator_ceremony",
        "status": "template_pending_real_operator_ceremony",
        "generated_epoch": None,
        "model_output_is_not_authority": True,
        "package_id": package_id,
        "package_manifest_sha256": sha256(manifest_path),
        "root_distribution_sha256": files["trusted_root_distribution"]["sha256"],
        "keyring_sha256": files["trusted_keyring"]["sha256"],
        "root_key_id": "TO_BE_FILLED_FROM_PROTECTED_ROOT",
        "protected_root": {
            "storage_class": "TO_BE_FILLED",
            "offline": False,
            "private_key_exported": True,
            "recovery_tested": False,
            "operator_witnesses": [],
        },
        "trusted_distribution": {
            "root_distribution_sha256": files["trusted_root_distribution"]["sha256"],
            "channels": [],
            "verification_receipts": [],
        },
        "rotation": {"tested": False, "operator_approved": False, "events": []},
        "revocation": {"tested": False, "rejection_evidence": []},
        "release_binding": {
            "source_revision": args.source_revision,
            "release_id": "TO_BE_FILLED",
            "attestation_sha256": sha256(args.attestation),
        },
    }
    (root / "operational-proof-template.json").write_text(json.dumps(template, indent=2, sort_keys=True) + "\n")
    readme = f"""# FAISAL Signing-Authority Operational-Proof Package\n\nPackage: `{package_id}`\n\nThis package contains public trust metadata, the signed keyring, the release attestation, validators, and the ceremony runbook. It contains **no private key**. The template is deliberately non-authoritative and must be replaced by an actual operator ceremony record.\n\nThe production gate must receive a completed proof signed by the protected root key. The proof must demonstrate protected root custody, at least two distinct operator witnesses, two trusted distribution channels with verification receipts, release binding, a tested key rotation, explicit old-key revocation and rejection, and recovery.\n\nThe sandbox can validate the schema and simulate cryptographic behavior with temporary test keys, but it cannot claim production custody, human witness presence, HSM protection, air-gap protection, or trusted distribution.\n"""
    (root / "README.md").write_text(readme)
    checksums = [f"{sha256(path)}  {path.relative_to(root)}" for path in sorted(p for p in root.rglob("*") if p.is_file())]
    (root / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    archive = output / f"{package_id}.tar.gz"
    if archive.exists():
        archive.unlink()
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(root, arcname=root.name)
    output_manifest = output / "operational-proof-package.json"
    shutil.copy2(manifest_path, output_manifest)
    print(f"FAISAL_SIGNING_AUTHORITY_PACKAGE_READY package={package_id} manifest={output_manifest} archive={archive}")
    print(f"manifest_sha256={sha256(output_manifest)} archive_sha256={sha256(archive)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
