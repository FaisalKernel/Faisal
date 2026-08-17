#!/usr/bin/env python3
"""FAISAL operator-controlled release authority.

The tool deliberately keeps private keys outside generated release metadata.
An offline/root key signs the trusted release-key distribution. An active
operator release key signs a specific artifact set plus an explicit approval
record. Verification requires both signatures and all digest/policy bindings.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCHEMA_KEYRING = "org.faisal.trusted-keyring.v1"
SCHEMA_ROOT = "org.faisal.trusted-root.v1"
SCHEMA_ATTESTATION = "org.faisal.release-attestation.v1"
ALGORITHM = "RSA-SHA256"


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"FAISAL_RELEASE_AUTHORITY_FAIL:{message}")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON object required: {path}")
    return value


def write_atomic(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")
    return digest.hexdigest()


def openssl(*args: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *args],
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"")
        fail(f"openssl operation failed: {detail.decode(errors='replace').strip()}")
    return result.stdout


def public_key_pem(private_key: Path) -> bytes:
    return openssl("pkey", "-in", str(private_key), "-pubout")


def public_key_id(pem: bytes) -> str:
    der = openssl("pkey", "-pubin", "-inform", "PEM", "-in", "/dev/stdin", "-outform", "DER", input_data=pem)
    return hashlib.sha256(der).hexdigest()[:32]


def sign_bytes(private_key: Path, payload: bytes) -> bytes:
    return openssl("dgst", "-sha256", "-sign", str(private_key), input_data=payload)


def verify_bytes(public_pem: bytes, signature: bytes, payload: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="faisal-release-verify-") as directory:
        root = Path(directory)
        public_path = root / "public.pem"
        signature_path = root / "signature.bin"
        payload_path = root / "payload.bin"
        public_path.write_bytes(public_pem)
        signature_path.write_bytes(signature)
        payload_path.write_bytes(payload)
        try:
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(public_path),
                 "-signature", str(signature_path), str(payload_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError):
            fail("signature verification failed")


def read_private_key(path: Path) -> bytes:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            fail(f"private key is group/world writable: {path}")
        return path.read_bytes()
    except OSError as exc:
        fail(f"private key unavailable: {exc}")


def ensure_epoch(value: object, field: str) -> int:
    if not isinstance(value, int) or value < 0:
        fail(f"invalid {field}")
    return value


def command_create_keyring(args: argparse.Namespace) -> None:
    root_private = Path(args.root_private_key)
    release_private = Path(args.release_private_key)
    root_pem = public_key_pem(root_private)
    release_pem = public_key_pem(release_private)
    root_id = public_key_id(root_pem)
    release_id = public_key_id(release_pem)
    now = int(time.time())
    not_before = args.not_before if args.not_before is not None else now
    not_after = args.not_after if args.not_after is not None else now + 365 * 24 * 3600
    if not_after <= not_before:
        fail("key validity interval is empty")
    keyring = {
        "schema": SCHEMA_KEYRING,
        "project": "FAISAL",
        "generation": args.generation,
        "created_epoch": now,
        "expires_epoch": not_after,
        "root_key_id": root_id,
        "keys": [{
            "key_id": release_id,
            "algorithm": ALGORITHM,
            "public_key_pem": release_pem.decode(),
            "not_before_epoch": not_before,
            "not_after_epoch": not_after,
            "status": "active",
        }],
        "revoked_key_ids": [],
        "rotation_policy": {
            "requires_root_signature": True,
            "operator_approval_required": True,
            "old_keys_must_be_explicitly_revoked": True,
        },
    }
    keyring_path = Path(args.keyring)
    keyring_bytes = canonical(keyring)
    write_atomic(keyring_path, keyring_bytes)
    write_atomic(Path(f"{keyring_path}.sig"), sign_bytes(root_private, keyring_bytes))
    root_distribution = {
        "schema": SCHEMA_ROOT,
        "project": "FAISAL",
        "root_key_id": root_id,
        "algorithm": ALGORITHM,
        "public_key_pem": root_pem.decode(),
        "distribution_policy": {
            "operator_controlled": True,
            "private_key_must_not_be_distributed": True,
            "keyring_signature_required": True,
        },
    }
    write_atomic(Path(args.root_distribution), canonical(root_distribution))
    print(f"FAISAL_TRUSTED_KEYRING_CREATED keyring={keyring_path} root_key_id={root_id} release_key_id={release_id}")


def command_rotate(args: argparse.Namespace) -> None:
    root_private = Path(args.root_private_key)
    old_keyring_path = Path(args.keyring)
    old = load_json(old_keyring_path)
    if old.get("schema") != SCHEMA_KEYRING:
        fail("unexpected keyring schema")
    release_private = Path(args.release_private_key)
    release_pem = public_key_pem(release_private)
    release_id = public_key_id(release_pem)
    now = int(time.time())
    not_before = args.not_before if args.not_before is not None else now
    not_after = args.not_after if args.not_after is not None else now + 365 * 24 * 3600
    if not_after <= not_before:
        fail("key validity interval is empty")
    keys = list(old.get("keys", []))
    revoked = list(old.get("revoked_key_ids", []))
    if any(key.get("key_id") == release_id for key in keys):
        fail("new key already exists")
    if args.revoke_key_id:
        found = False
        for key in keys:
            if key.get("key_id") == args.revoke_key_id:
                key["status"] = "revoked"
                found = True
        if not found:
            fail("rotation target key not found")
        if args.revoke_key_id not in revoked:
            revoked.append(args.revoke_key_id)
    keys.append({
        "key_id": release_id,
        "algorithm": ALGORITHM,
        "public_key_pem": release_pem.decode(),
        "not_before_epoch": not_before,
        "not_after_epoch": not_after,
        "status": "active",
    })
    rotated = dict(old)
    rotated["generation"] = ensure_epoch(old.get("generation"), "generation") + 1
    rotated["created_epoch"] = now
    rotated["expires_epoch"] = max(ensure_epoch(old.get("expires_epoch"), "expires_epoch"), not_after)
    rotated["keys"] = keys
    rotated["revoked_key_ids"] = sorted(set(revoked))
    data = canonical(rotated)
    write_atomic(old_keyring_path, data)
    write_atomic(Path(f"{old_keyring_path}.sig"), sign_bytes(root_private, data))
    print(f"FAISAL_TRUSTED_KEYRING_ROTATED generation={rotated['generation']} release_key_id={release_id} revoked={args.revoke_key_id or 'none'}")


def check_approval(path: Path) -> dict:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        fail(f"operator approval unavailable: {exc}")
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        fail("operator approval is group/world writable")
    approval = load_json(path)
    if approval.get("schema") != "org.faisal.operator-approval.v1":
        fail("invalid operator approval schema")
    if approval.get("approved") is not True:
        fail("operator approval is not affirmative")
    for field in ("approval_id", "approved_by", "scope", "expires_epoch"):
        if not approval.get(field):
            fail(f"operator approval missing {field}")
    if ensure_epoch(approval["expires_epoch"], "approval expiry") <= int(time.time()):
        fail("operator approval expired")
    if approval["scope"] != "FAISAL-production-release":
        fail("operator approval scope mismatch")
    return approval


def artifact_set(args: argparse.Namespace) -> dict:
    paths = {
        "manifest": Path(args.manifest),
        "sbom": Path(args.sbom),
        "checksums": Path(args.checksums),
    }
    result = {}
    for name, path in paths.items():
        if not path.is_file():
            fail(f"artifact missing: {path}")
        result[name] = {"path": str(path), "sha256": sha256_file(path)}
    return result


def find_release_key(keyring: dict, key_id: str, created: int) -> dict:
    if key_id in keyring.get("revoked_key_ids", []):
        fail("release key is revoked")
    for key in keyring.get("keys", []):
        if key.get("key_id") == key_id:
            if key.get("status") != "active":
                fail("release key is not active")
            if not (ensure_epoch(key.get("not_before_epoch"), "key not-before") <= created <= ensure_epoch(key.get("not_after_epoch"), "key not-after")):
                fail("release key outside validity interval")
            return key
    fail("release key is not trusted")


def command_sign(args: argparse.Namespace) -> None:
    keyring_path = Path(args.keyring)
    keyring = load_json(keyring_path)
    if keyring.get("schema") != SCHEMA_KEYRING:
        fail("unexpected keyring schema")
    approval_path = Path(args.operator_approval)
    approval = check_approval(approval_path)
    release_private = Path(args.release_private_key)
    release_pem = public_key_pem(release_private)
    release_id = public_key_id(release_pem)
    created = int(time.time())
    find_release_key(keyring, release_id, created)
    artifacts = artifact_set(args)
    attestation = {
        "schema": SCHEMA_ATTESTATION,
        "project": "FAISAL",
        "release_id": args.release_id,
        "created_epoch": created,
        "release_key_id": release_id,
        "algorithm": ALGORITHM,
        "keyring_sha256": sha256_file(keyring_path),
        "operator_approval": {
            "approval_id": approval["approval_id"],
            "approved_by": approval["approved_by"],
            "approval_sha256": sha256_file(approval_path),
            "expires_epoch": approval["expires_epoch"],
        },
        "artifacts": artifacts,
        "policy": {
            "model_output_is_not_authority": True,
            "operator_approval_required": True,
            "trusted_key_distribution_required": True,
            "rollback_requires_new_verified_attestation": True,
        },
    }
    data = canonical(attestation)
    output = Path(args.attestation)
    write_atomic(output, data)
    write_atomic(Path(f"{output}.sig"), sign_bytes(release_private, data))
    print(f"FAISAL_RELEASE_ATTESTATION_CREATED release_id={args.release_id} release_key_id={release_id} attestation={output}")


def command_verify(args: argparse.Namespace) -> None:
    root = load_json(Path(args.root_distribution))
    keyring_path = Path(args.keyring)
    keyring = load_json(keyring_path)
    attestation_path = Path(args.attestation)
    attestation = load_json(attestation_path)
    if root.get("schema") != SCHEMA_ROOT or keyring.get("schema") != SCHEMA_KEYRING:
        fail("trusted metadata schema mismatch")
    root_pem = root.get("public_key_pem", "").encode()
    if public_key_id(root_pem) != root.get("root_key_id"):
        fail("trusted root key id mismatch")
    if keyring.get("root_key_id") != root.get("root_key_id"):
        fail("keyring root binding mismatch")
    keyring_sig = Path(f"{keyring_path}.sig")
    if not keyring_sig.is_file():
        fail("trusted keyring signature missing")
    verify_bytes(root_pem, keyring_sig.read_bytes(), canonical(keyring))
    if attestation.get("schema") != SCHEMA_ATTESTATION:
        fail("release attestation schema mismatch")
    created = ensure_epoch(attestation.get("created_epoch"), "attestation created_epoch")
    if created > int(time.time()) + args.future_skew:
        fail("attestation timestamp is in the future")
    if int(time.time()) - created > args.max_age:
        fail("release attestation is stale")
    release_key = find_release_key(keyring, attestation.get("release_key_id", ""), created)
    public_pem = release_key.get("public_key_pem", "").encode()
    attestation_sig = Path(f"{attestation_path}.sig")
    if not attestation_sig.is_file():
        fail("release attestation signature missing")
    verify_bytes(public_pem, attestation_sig.read_bytes(), canonical(attestation))
    if attestation.get("keyring_sha256") != sha256_file(keyring_path):
        fail("attestation keyring digest mismatch")
    approval = attestation.get("operator_approval", {})
    if not approval.get("approval_id") or not approval.get("approved_by"):
        fail("operator approval binding missing")
    if ensure_epoch(approval.get("expires_epoch"), "approval expiry") < created:
        fail("operator approval expired at release time")
    expected = artifact_set(args)
    recorded = attestation.get("artifacts", {})
    if set(recorded) != set(expected):
        fail("artifact set mismatch")
    for name, item in expected.items():
        if recorded[name].get("sha256") != item["sha256"]:
            fail(f"artifact digest mismatch: {name}")
    report = Path(args.report)
    write_atomic(report, ("check\tstatus\tdetail\n"
                          f"root_trust\tpass\t{root['root_key_id']}\n"
                          f"keyring_signature\tpass\tgeneration={keyring['generation']}\n"
                          f"release_signature\tpass\t{attestation['release_key_id']}\n"
                          f"operator_approval\tpass\t{approval['approval_id']}:{approval['approved_by']}\n"
                          "artifact_digests\tpass\tmanifest-sbom-checksums\n").encode())
    print(f"FAISAL_RELEASE_AUTHORITY_VERIFY_OK report={report} release_id={attestation['release_id']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-keyring")
    create.add_argument("--root-private-key", required=True)
    create.add_argument("--release-private-key", required=True)
    create.add_argument("--keyring", required=True)
    create.add_argument("--root-distribution", required=True)
    create.add_argument("--generation", type=int, default=1)
    create.add_argument("--not-before", type=int)
    create.add_argument("--not-after", type=int)
    create.set_defaults(function=command_create_keyring)
    rotate = sub.add_parser("rotate-keyring")
    rotate.add_argument("--root-private-key", required=True)
    rotate.add_argument("--release-private-key", required=True)
    rotate.add_argument("--keyring", required=True)
    rotate.add_argument("--revoke-key-id")
    rotate.add_argument("--not-before", type=int)
    rotate.add_argument("--not-after", type=int)
    rotate.set_defaults(function=command_rotate)
    sign = sub.add_parser("sign")
    sign.add_argument("--release-private-key", required=True)
    sign.add_argument("--keyring", required=True)
    sign.add_argument("--operator-approval", required=True)
    sign.add_argument("--release-id", required=True)
    sign.add_argument("--manifest", required=True)
    sign.add_argument("--sbom", required=True)
    sign.add_argument("--checksums", required=True)
    sign.add_argument("--attestation", required=True)
    sign.set_defaults(function=command_sign)
    verify = sub.add_parser("verify")
    verify.add_argument("--root-distribution", required=True)
    verify.add_argument("--keyring", required=True)
    verify.add_argument("--attestation", required=True)
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--sbom", required=True)
    verify.add_argument("--checksums", required=True)
    verify.add_argument("--report", required=True)
    verify.add_argument("--max-age", type=int, default=30 * 24 * 3600)
    verify.add_argument("--future-skew", type=int, default=300)
    verify.set_defaults(function=command_verify)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
