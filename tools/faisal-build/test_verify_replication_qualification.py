#!/usr/bin/env python3
"""Synthetic tests for the signed full TLS replication evidence gate."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

import verify_replication_qualification as validator

REVISION = "2" * 40
NOW = 1800000000


def signed_fixture(directory: Path, data: dict) -> tuple[Path, Path, Path]:
    private = directory / "private.pem"
    public = directory / "public.pem"
    report = directory / "replication.json"
    signature = Path(f"{report}.sig")
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(report)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return report, signature, public


def good() -> dict:
    return {
        "schema": validator.SCHEMA,
        "source_revision": REVISION,
        "reviewed_epoch": NOW,
        "status": "pass_software_fixture_physical_and_production_pkI_pending",
        "transport": "gRPC_TLS_mutual_authentication",
        "authenticated_quorum_certificate": True,
        "minority_partition_commit_denied": True,
        "durable_state_reload": True,
        "model_output_is_authority": False,
        "markers": sorted(validator.REQUIRED_MARKERS),
        "limitations": ["software fixture only; physical qualification pending"],
    }


def expect_failure(directory: Path, data: dict, label: str) -> None:
    report, _signature, public = signed_fixture(directory, data)
    try:
        validator.verify(report, public, REVISION, NOW, 3600)
    except ValueError:
        return
    raise AssertionError(f"expected failure: {label}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="faisal-replication-validator-") as raw:
        directory = Path(raw)
        report, _signature, public = signed_fixture(directory, good())
        result = validator.verify(report, public, REVISION, NOW, 3600)
        assert result["authenticated_quorum_certificate"] is True

        tampered = json.loads(report.read_text())
        tampered["markers"] = []
        expect_failure(directory, tampered, "missing markers")

        stale = good()
        stale["reviewed_epoch"] = NOW - 3601
        expect_failure(directory, stale, "stale report")

        wrong_source = good()
        wrong_source["source_revision"] = "3" * 40
        expect_failure(directory, wrong_source, "source mismatch")

        no_boundary = good()
        no_boundary["status"] = "pass"
        expect_failure(directory, no_boundary, "missing production boundary")

        no_authority = good()
        no_authority["model_output_is_authority"] = True
        expect_failure(directory, no_authority, "model authority")

        report.write_text(report.read_text().replace("gRPC_TLS_mutual_authentication", "tampered"))
        try:
            validator.verify(report, public, REVISION, NOW, 3600)
        except ValueError:
            pass
        else:
            raise AssertionError("signature tampering accepted")

    print("FAISAL_REPLICATION_VALIDATOR_TEST_OK signed_positive_stale_source_marker_boundary_authority_tamper_denied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
