#!/usr/bin/env python3
"""Fail-closed FAISAL deployment, migration, canary, and rollback gate."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "org.faisal.deployment-governance.v1"


def fail(message: str) -> None:
    raise ValueError(message)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def nonzero_hex(value: object, length: int = 64) -> bool:
    return isinstance(value, str) and len(value) == length and value != "0" * length and all(c in "0123456789abcdef" for c in value.lower())


def verify(report: Path, public_key: Path, expected_revision: str, now: int, max_age: int) -> dict:
    if report.suffix != ".json":
        fail("structured JSON deployment evidence is required")
    signature = Path(f"{report}.sig")
    if not report.is_file() or not signature.is_file() or not public_key.is_file():
        fail("deployment evidence, detached signature, and public key are required")
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(report)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail("deployment evidence signature mismatch")
    data = json.loads(report.read_text())
    if data.get("schema") != SCHEMA:
        fail("deployment-governance schema mismatch")
    if data.get("source_revision") != expected_revision:
        fail("deployment source revision mismatch")
    reviewed = data.get("reviewed_epoch")
    if not isinstance(reviewed, int) or reviewed > now or now - reviewed > max_age:
        fail("deployment evidence is stale or timestamp is invalid")
    if data.get("model_output_is_authority") is not False:
        fail("model output cannot authorize deployment")
    candidate = data.get("candidate")
    previous = data.get("previous_active")
    rollback = data.get("rollback_target")
    migration = data.get("migration")
    approvals = data.get("approvals")
    canary = data.get("canary")
    rollback_evidence = data.get("rollback")
    for name, item in (("candidate", candidate), ("previous_active", previous), ("rollback_target", rollback), ("migration", migration), ("approvals", approvals), ("canary", canary), ("rollback", rollback_evidence)):
        if not isinstance(item, dict):
            fail(f"{name} section missing")
    if not nonzero_hex(candidate.get("artifact_sha256")) or not nonzero_hex(candidate.get("state_digest")):
        fail("candidate artifact/state digest missing")
    if not candidate.get("build_id") or not candidate.get("revision_id"):
        fail("candidate identity missing")
    if not isinstance(candidate.get("abi"), int) or not isinstance(candidate.get("schema_version"), int):
        fail("candidate ABI/schema missing")
    candidate_binding = digest({
        "revision_id": candidate["revision_id"],
        "build_id": candidate["build_id"],
        "artifact_sha256": candidate["artifact_sha256"],
        "state_digest": candidate["state_digest"],
        "abi": candidate["abi"],
        "schema_version": candidate["schema_version"],
        "policy_generation": candidate.get("policy_generation"),
    })
    if data.get("candidate_binding_sha256") != candidate_binding:
        fail("candidate binding digest mismatch")
    if previous.get("revision_id") == candidate.get("revision_id") or not nonzero_hex(previous.get("artifact_sha256")):
        fail("previous active revision is missing or not distinct")
    if rollback.get("revision_id") != previous.get("revision_id") or rollback.get("artifact_sha256") != previous.get("artifact_sha256"):
        fail("rollback target is not the verified previous active revision")
    if not nonzero_hex(rollback.get("state_digest")) or not isinstance(rollback.get("checkpoint_id"), int) or rollback.get("checkpoint_id") <= 0:
        fail("rollback checkpoint/state evidence missing")
    if migration.get("from_revision") != previous.get("revision_id") or migration.get("to_revision") != candidate.get("revision_id"):
        fail("migration endpoints do not bind to active and candidate revisions")
    if migration.get("from_abi") != previous.get("abi") or migration.get("to_abi") != candidate.get("abi"):
        fail("migration ABI endpoints do not bind to revisions")
    if migration.get("compatible") is not True or migration.get("state_schema_compatible") is not True:
        fail("migration compatibility is not explicitly verified")
    if not migration.get("migration_id") or not nonzero_hex(migration.get("handoff_token_sha256")):
        fail("migration identity or handoff token digest missing")
    if not isinstance(migration.get("worker_fence_epoch"), int) or migration["worker_fence_epoch"] <= int(migration.get("previous_worker_fence_epoch", 0)):
        fail("worker migration fence did not advance")
    if not isinstance(migration.get("handoff_deadline_epoch"), int) or migration["handoff_deadline_epoch"] <= reviewed:
        fail("migration handoff deadline is invalid")
    for role in ("supervisor", "operator", "integrity"):
        approval = approvals.get(role)
        if not isinstance(approval, dict) or approval.get("approved") is not True or approval.get("binds_to") != candidate_binding or not approval.get("evidence"):
            fail(f"{role} approval is missing or not candidate-bound")
    if canary.get("required") is not True or canary.get("health_ok") is not True or canary.get("promotion_allowed") is not True:
        fail("canary promotion is not explicitly healthy and allowed")
    if not isinstance(canary.get("sampled_at_epoch"), int) or canary["sampled_at_epoch"] < reviewed:
        fail("canary observation timestamp is invalid")
    if canary.get("rollback_on_failure_tested") is not True:
        fail("canary failure rollback test is missing")
    if rollback_evidence.get("tested") is not True or rollback_evidence.get("recovery_verified") is not True or rollback_evidence.get("target_digest") != rollback.get("artifact_sha256"):
        fail("rollback target or recovery verification is not bound")
    if rollback_evidence.get("idempotent_replay") is not True or rollback_evidence.get("stale_worker_fenced") is not True:
        fail("rollback replay or stale-worker fencing evidence missing")
    limitations = data.get("limitations")
    if not isinstance(limitations, list) or not limitations:
        fail("explicit deployment limitations are required")
    if data.get("production_status") != "bounded_software_governance_qualified_external_operation_pending":
        fail("production boundary is missing or overstated")
    return data


def main() -> int:
    report = Path(os.environ.get("FAISAL_DEPLOYMENT_EVIDENCE", ""))
    public_key = Path(os.environ.get("FAISAL_PUBLIC_KEY", ""))
    expected = os.environ.get("FAISAL_EXPECTED_SOURCE_REV", "")
    output = Path(os.environ.get("FAISAL_DEPLOYMENT_VERIFY_REPORT", f"{report}.verification.tsv"))
    try:
        now = int(os.environ.get("FAISAL_DEPLOYMENT_NOW_EPOCH", str(int(time.time()))))
        max_age = int(os.environ.get("FAISAL_DEPLOYMENT_MAX_AGE_SECONDS", str(30 * 24 * 60 * 60)))
        data = verify(report, public_key, expected, now, max_age)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("check\tstatus\tdetail\ndeployment_governance\tpass\t" + str(data["candidate"]["revision_id"]) + "\n")
        print(f"FAISAL_DEPLOYMENT_GOVERNANCE_OK report={output}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"check\tstatus\tdetail\ndeployment_governance\tblocked\t{exc}\n")
        print(f"FAISAL_DEPLOYMENT_GOVERNANCE_BLOCKED reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
