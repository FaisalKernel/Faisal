#!/usr/bin/env python3
"""FAISAL independent-builder / attested-build-farm qualification gate.

The verifier deliberately does not manufacture independence. A report created by
record-local is useful for reproducibility diagnostics only and is rejected by
verify because a container machine-id is not an independent physical-builder or
provider attestation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = "org.faisal.builder-attestation.v1"
ALLOWED_EXTERNAL_EVIDENCE = {"physical_host_measurement", "provider_attestation"}
FORBIDDEN_EVIDENCE = {"local_machine_id", "container_machine_id", "self_report"}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_openssl(args: list[str], payload: bytes | None = None) -> bytes:
    proc = subprocess.run(["openssl", *args], input=payload, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)
    if proc.returncode:
        raise ValueError(proc.stderr.decode(errors="replace").strip() or "openssl failed")
    return proc.stdout


def sign_payload(payload: bytes, private_key: Path) -> str:
    with tempfile.NamedTemporaryFile() as data_file:
        data_file.write(payload)
        data_file.flush()
        signature = run_openssl(["dgst", "-sha256", "-sign", str(private_key), data_file.name])
    return base64.b64encode(signature).decode("ascii")


def verify_signature(payload: bytes, signature_b64: str, public_key: Path) -> None:
    signature = base64.b64decode(signature_b64, validate=True)
    with tempfile.NamedTemporaryFile() as data_file, tempfile.NamedTemporaryFile() as sig_file:
        data_file.write(payload)
        data_file.flush()
        sig_file.write(signature)
        sig_file.flush()
        run_openssl(["dgst", "-sha256", "-verify", str(public_key), "-signature", sig_file.name, data_file.name])


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return data


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def artifact_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    artifacts = report["signed_payload"].get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "signed_payload.artifacts is empty")
    result: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        require(isinstance(item, dict), "artifact entry is not an object")
        name = item.get("name")
        digest = item.get("sha256")
        size = item.get("size")
        require(isinstance(name, str) and name, "artifact name missing")
        require(isinstance(digest, str) and len(digest) == 64, f"artifact digest missing: {name}")
        require(isinstance(size, int) and size >= 0, f"artifact size missing: {name}")
        require(name not in result, f"duplicate artifact: {name}")
        result[name] = item
    return result


def verify_report(path: Path, public_key: Path, expected_role: str) -> dict[str, Any]:
    report = load_json(path)
    require(report.get("schema") == SCHEMA, f"schema mismatch in {path}")
    payload = report.get("signed_payload")
    signature = report.get("signature")
    require(isinstance(payload, dict), f"signed_payload missing in {path}")
    require(isinstance(signature, dict), f"signature missing in {path}")
    require(signature.get("algorithm") == "RSA-SHA256", f"unsupported signature algorithm in {path}")
    signature_b64 = signature.get("value_base64")
    require(isinstance(signature_b64, str) and signature_b64, f"signature value missing in {path}")
    verify_signature(canonical(payload), signature_b64, public_key)
    require(payload.get("builder_role") == expected_role,
            f"builder role mismatch in {path}; expected {expected_role}")
    identity = payload.get("builder_identity")
    require(isinstance(identity, dict), f"builder_identity missing in {path}")
    identity_digest = identity.get("identity_digest_sha256")
    evidence_type = identity.get("evidence_type")
    require(isinstance(identity_digest, str) and len(identity_digest) == 64,
            f"builder identity digest missing in {path}")
    require(evidence_type not in FORBIDDEN_EVIDENCE,
            f"self-reported/local identity is not qualifying evidence in {path}")
    require(evidence_type in ALLOWED_EXTERNAL_EVIDENCE,
            f"external identity evidence type required in {path}")
    issuer = identity.get("issuer")
    require(isinstance(issuer, str) and issuer.strip(), f"identity issuer missing in {path}")
    artifact_map(report)
    return report


def command_record_local(args: argparse.Namespace) -> int:
    source = Path(args.source).resolve()
    artifact = Path(args.artifact).resolve()
    require(source.exists(), f"source does not exist: {source}")
    require(artifact.exists(), f"artifact does not exist: {artifact}")
    machine_id = Path("/etc/machine-id").read_text().strip()
    payload = {
        "schema_version": 1,
        "builder_role": args.role,
        "builder_id": args.builder_id,
        "source_revision": args.source_revision,
        "config_sha256": args.config_sha256,
        "builder_identity": {
            "evidence_type": "container_machine_id",
            "issuer": "local-sandbox-self-report",
            "identity_digest_sha256": hashlib.sha256(machine_id.encode()).hexdigest(),
            "measurement": "sha256(/etc/machine-id)",
            "qualification_note": "reproducibility diagnostic only; not an independent physical-builder or provider attestation"
        },
        "artifacts": [{
            "name": artifact.name,
            "sha256": sha256_file(artifact),
            "size": artifact.stat().st_size
        }]
    }
    report = {
        "schema": SCHEMA,
        "signed_payload": payload,
        "signature": {
            "algorithm": "RSA-SHA256",
            "value_base64": sign_payload(canonical(payload), Path(args.private_key)),
            "key_file": str(Path(args.public_key).resolve())
        }
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"FAISAL_BUILDER_REPORT_CREATED report={output} role={args.role} evidence_type=container_machine_id")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    try:
        primary = verify_report(Path(args.primary), Path(args.primary_key), "primary")
        secondary = verify_report(Path(args.secondary), Path(args.secondary_key), "independent")
        primary_payload = primary["signed_payload"]
        secondary_payload = secondary["signed_payload"]
        require(primary_payload.get("source_revision") == secondary_payload.get("source_revision"),
                "source revisions differ")
        require(primary_payload.get("config_sha256") == secondary_payload.get("config_sha256"),
                "configuration digests differ")
        primary_identity = primary_payload["builder_identity"]["identity_digest_sha256"]
        secondary_identity = secondary_payload["builder_identity"]["identity_digest_sha256"]
        require(primary_identity != secondary_identity,
                "builder identity digests match; same-host or duplicated identity")
        primary_artifacts = artifact_map(primary)
        secondary_artifacts = artifact_map(secondary)
        require(set(primary_artifacts) == set(secondary_artifacts), "artifact sets differ")
        for name in sorted(primary_artifacts):
            require(primary_artifacts[name]["sha256"] == secondary_artifacts[name]["sha256"],
                    f"artifact digest differs: {name}")
            require(primary_artifacts[name]["size"] == secondary_artifacts[name]["size"],
                    f"artifact size differs: {name}")
        result = {
            "schema": "org.faisal.builder-qualification-result.v1",
            "result": "pass",
            "primary_report": str(Path(args.primary).resolve()),
            "secondary_report": str(Path(args.secondary).resolve()),
            "source_revision": primary_payload["source_revision"],
            "config_sha256": primary_payload["config_sha256"],
            "artifact_digests": {name: primary_artifacts[name]["sha256"] for name in sorted(primary_artifacts)},
            "identity_digests": {"primary": primary_identity, "independent": secondary_identity},
            "qualification_boundary": "external signed identity evidence verified; physical independence is accepted only from the declared external evidence type and issuer"
        }
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"FAISAL_BUILDER_QUALIFICATION_OK source={result['source_revision']} artifacts={len(primary_artifacts)}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        if args.output:
            Path(args.output).write_text(json.dumps({
                "schema": "org.faisal.builder-qualification-result.v1",
                "result": "blocked",
                "reason": str(exc)
            }, indent=2, sort_keys=True) + "\n")
        print(f"FAISAL_BUILDER_QUALIFICATION_BLOCKED reason={exc}", file=sys.stderr)
        return 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    record = sub.add_parser("record-local")
    record.add_argument("--source", required=True)
    record.add_argument("--artifact", required=True)
    record.add_argument("--source-revision", required=True)
    record.add_argument("--config-sha256", required=True)
    record.add_argument("--builder-id", required=True)
    record.add_argument("--role", choices=("primary", "independent"), required=True)
    record.add_argument("--private-key", required=True)
    record.add_argument("--public-key", required=True)
    record.add_argument("--output", required=True)
    record.set_defaults(func=command_record_local)
    verify = sub.add_parser("verify")
    verify.add_argument("--primary", required=True)
    verify.add_argument("--primary-key", required=True)
    verify.add_argument("--secondary", required=True)
    verify.add_argument("--secondary-key", required=True)
    verify.add_argument("--output")
    verify.set_defaults(func=command_verify)
    return root


if __name__ == "__main__":
    args = parser().parse_args()
    raise SystemExit(args.func(args))
