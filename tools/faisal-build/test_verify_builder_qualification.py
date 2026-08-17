#!/usr/bin/env python3
"""Unit tests for verify_builder_qualification.py.

All external-attestation fixtures here are synthetic test data. They validate
cryptographic and policy logic only; they are never production qualification.
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

import verify_builder_qualification as verifier


def keypair(directory: Path, name: str) -> tuple[Path, Path]:
    private = directory / f"{name}-private.pem"
    public = directory / f"{name}-public.pem"
    subprocess.run([
        "openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-out", str(private)
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return private, public


def report(directory: Path, role: str, private: Path, evidence_type: str, identity: str) -> Path:
    payload = {
        "schema_version": 1,
        "builder_role": role,
        "source_revision": "test-source-revision",
        "config_sha256": "0" * 64,
        "builder_identity": {
            "evidence_type": evidence_type,
            "issuer": "synthetic-test-root",
            "identity_digest_sha256": hashlib.sha256(identity.encode()).hexdigest(),
        },
        "artifacts": [{"name": "bzImage", "sha256": "1" * 64, "size": 7}],
    }
    signed = verifier.sign_payload(verifier.canonical(payload), private)
    output = directory / f"{role}-report.json"
    output.write_text(json.dumps({
        "schema": verifier.SCHEMA,
        "signed_payload": payload,
        "signature": {"algorithm": "RSA-SHA256", "value_base64": signed},
    }, indent=2) + "\n")
    return output


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="faisal-builder-verifier-test-") as raw:
        directory = Path(raw)
        primary_private, primary_public = keypair(directory, "primary")
        secondary_private, secondary_public = keypair(directory, "secondary")
        primary = report(directory, "primary", primary_private, "provider_attestation", "provider-a")
        secondary = report(directory, "independent", secondary_private, "physical_host_measurement", "host-b")
        output = directory / "qualification.json"
        args = type("Args", (), {
            "primary": str(primary), "primary_key": str(primary_public),
            "secondary": str(secondary), "secondary_key": str(secondary_public),
            "output": str(output),
        })()
        assert verifier.command_verify(args) == 0
        assert json.loads(output.read_text())["result"] == "pass"

        tampered = json.loads(secondary.read_text())
        tampered["signed_payload"]["artifacts"][0]["sha256"] = "2" * 64
        secondary.write_text(json.dumps(tampered))
        assert verifier.command_verify(args) == 1
        assert json.loads(output.read_text())["result"] == "blocked"

        local = report(directory, "independent", secondary_private, "container_machine_id", "host-b")
        args.secondary = str(local)
        assert verifier.command_verify(args) == 1

    print("FAISAL_BUILDER_VERIFIER_UNIT_OK synthetic_external_pass_tamper_denied_local_identity_denied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
