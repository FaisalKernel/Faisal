#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
from pathlib import Path

import verify_deployment_governance as validator

REVISION = "4" * 40
NOW = 1800000000


def good() -> dict:
    candidate = {
        "revision_id": "rev-candidate-172",
        "build_id": "faisal-build-172",
        "artifact_sha256": "a" * 64,
        "state_digest": "b" * 64,
        "abi": 38,
        "schema_version": 3,
        "policy_generation": 172,
    }
    previous = {
        "revision_id": "rev-active-171",
        "build_id": "faisal-build-171",
        "artifact_sha256": "c" * 64,
        "state_digest": "d" * 64,
        "abi": 38,
        "schema_version": 3,
    }
    rollback = {
        "revision_id": previous["revision_id"],
        "artifact_sha256": previous["artifact_sha256"],
        "state_digest": previous["state_digest"],
        "checkpoint_id": 172001,
    }
    binding = validator.digest({
        "revision_id": candidate["revision_id"],
        "build_id": candidate["build_id"],
        "artifact_sha256": candidate["artifact_sha256"],
        "state_digest": candidate["state_digest"],
        "abi": candidate["abi"],
        "schema_version": candidate["schema_version"],
        "policy_generation": candidate["policy_generation"],
    })
    approvals = {
        role: {"approved": True, "binds_to": binding, "evidence": f"signed-{role}-approval"}
        for role in ("supervisor", "operator", "integrity")
    }
    return {
        "schema": validator.SCHEMA,
        "source_revision": REVISION,
        "reviewed_epoch": NOW,
        "production_status": "bounded_software_governance_qualified_external_operation_pending",
        "model_output_is_authority": False,
        "candidate": candidate,
        "candidate_binding_sha256": binding,
        "previous_active": previous,
        "rollback_target": rollback,
        "migration": {
            "migration_id": "migration-172-171-to-172",
            "from_revision": previous["revision_id"],
            "to_revision": candidate["revision_id"],
            "from_abi": previous["abi"],
            "to_abi": candidate["abi"],
            "compatible": True,
            "state_schema_compatible": True,
            "handoff_token_sha256": "e" * 64,
            "previous_worker_fence_epoch": 171,
            "worker_fence_epoch": 172,
            "handoff_deadline_epoch": NOW + 300,
        },
        "approvals": approvals,
        "canary": {
            "required": True,
            "health_ok": True,
            "promotion_allowed": True,
            "sampled_at_epoch": NOW + 60,
            "rollback_on_failure_tested": True,
        },
        "rollback": {
            "tested": True,
            "recovery_verified": True,
            "target_digest": rollback["artifact_sha256"],
            "idempotent_replay": True,
            "stale_worker_fenced": True,
        },
        "limitations": ["software governance fixture only; external deployment operation pending"],
    }


def signed(directory: Path, data: dict) -> tuple[Path, Path]:
    private = directory / "private.pem"
    public = directory / "public.pem"
    report = directory / "deployment.json"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", f"{report}.sig", str(report)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return report, public


def expect_failure(directory: Path, data: dict, label: str) -> None:
    report, public = signed(directory, data)
    try:
        validator.verify(report, public, REVISION, NOW, 3600)
    except ValueError:
        return
    raise AssertionError(f"expected failure: {label}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="faisal-deployment-governance-") as raw:
        directory = Path(raw)
        report, public = signed(directory, good())
        assert validator.verify(report, public, REVISION, NOW, 3600)["candidate"]["revision_id"] == "rev-candidate-172"
        cli_report = directory / "deployment-verification.tsv"
        environment = os.environ.copy()
        environment.update({
            "FAISAL_DEPLOYMENT_EVIDENCE": str(report),
            "FAISAL_PUBLIC_KEY": str(public),
            "FAISAL_EXPECTED_SOURCE_REV": REVISION,
            "FAISAL_DEPLOYMENT_NOW_EPOCH": str(NOW),
            "FAISAL_DEPLOYMENT_VERIFY_REPORT": str(cli_report),
        })
        cli = subprocess.run(["python3", "tools/faisal-build/verify_deployment_governance.py"], cwd=Path(__file__).parents[2], env=environment, capture_output=True, text=True, check=False)
        assert cli.returncode == 0 and "FAISAL_DEPLOYMENT_GOVERNANCE_OK" in cli.stdout
        assert cli_report.is_file()

        tampered = good()
        tampered["rollback"]["target_digest"] = "f" * 64
        expect_failure(directory, tampered, "rollback target mismatch")

        no_operator = good()
        no_operator["approvals"]["operator"]["approved"] = False
        expect_failure(directory, no_operator, "operator approval")

        incompatible = good()
        incompatible["migration"]["state_schema_compatible"] = False
        expect_failure(directory, incompatible, "migration compatibility")

        stale_worker = good()
        stale_worker["migration"]["worker_fence_epoch"] = stale_worker["migration"]["previous_worker_fence_epoch"]
        expect_failure(directory, stale_worker, "worker fence")

        stale = good()
        stale["reviewed_epoch"] = NOW - 3601
        expect_failure(directory, stale, "stale evidence")

        model_authority = good()
        model_authority["model_output_is_authority"] = True
        expect_failure(directory, model_authority, "model authority")

        report.write_text(report.read_text().replace("rev-candidate-172", "tampered-revision"))
        try:
            validator.verify(report, public, REVISION, NOW, 3600)
        except ValueError:
            pass
        else:
            raise AssertionError("signature tampering accepted")
    print("FAISAL_DEPLOYMENT_GOVERNANCE_TEST_OK approval_binding_migration_fence_canary_rollback_stale_tamper_denied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
