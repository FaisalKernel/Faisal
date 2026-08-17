#!/usr/bin/env python3
"""Validate signed independent external security-review evidence."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "org.faisal.external-security-review.v1"
REQUIRED_DOMAINS = {
    "kernel_uapi_and_lifecycle",
    "capability_and_provenance_security",
    "memory_scheduler_and_resource_controls",
    "replication_tls_and_trust_providers",
    "accelerator_iommu_dma_and_driver_boundaries",
    "deployment_migration_and_rollback",
    "userspace_services_and_supply_chain",
}


def fail(message: str) -> None:
    raise ValueError(message)


def valid_hex(value: object, length: int = 64) -> bool:
    return isinstance(value, str) and len(value) == length and value != "0" * length and all(c in "0123456789abcdef" for c in value.lower())


def verify(report: Path, public_key: Path, expected_revision: str, now: int, max_age: int, require_external: bool = True) -> dict:
    if report.suffix != ".json":
        fail("structured JSON external-review evidence is required")
    signature = Path(f"{report}.sig")
    if not report.is_file() or not signature.is_file() or not public_key.is_file():
        fail("review report, detached signature, and reviewer public key are required")
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(report)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail("external-review signature mismatch")
    data = json.loads(report.read_text())
    if data.get("schema") != SCHEMA:
        fail("external-review schema mismatch")
    if data.get("source_revision") != expected_revision:
        fail("external-review source revision mismatch")
    reviewed = data.get("reviewed_epoch")
    if not isinstance(reviewed, int) or reviewed > now or now - reviewed > max_age:
        fail("external-review evidence is stale or timestamp is invalid")
    if data.get("model_output_is_authority") is not False:
        fail("model output cannot authorize security disposition")
    target = data.get("target")
    reviewer = data.get("reviewer")
    scope = data.get("scope")
    findings = data.get("findings")
    disposition = data.get("disposition")
    if not all(isinstance(x, dict) for x in (target, reviewer, scope, disposition)) or not isinstance(findings, list):
        fail("review target, reviewer, scope, findings, and disposition are required")
    if target.get("source_revision") != expected_revision or not valid_hex(target.get("artifact_sha256")) or not target.get("build_id"):
        fail("review target is not bound to the expected source and artifact")
    required_reviewer = ("organization", "reviewer_id", "qualification_evidence", "conflict_declaration", "independent_of_project")
    if any(key not in reviewer for key in required_reviewer):
        fail("reviewer independence record is incomplete")
    if reviewer.get("independent_of_project") is not True or reviewer.get("conflict_declaration") is not True:
        fail("reviewer independence or conflict declaration failed")
    if not reviewer.get("qualification_evidence"):
        fail("reviewer qualification evidence missing")
    if not reviewer.get("organization") or not reviewer.get("reviewer_id"):
        fail("reviewer identity missing")
    if require_external:
        if data.get("evidence_class") != "independent_external":
            fail("independent external evidence is required for production qualification")
        if reviewer.get("affiliation") in {"FAISAL", "FAISAL-project", "project-team", "internal"}:
            fail("project-affiliated reviewer is not independent")
        if reviewer.get("engagement_id") is None or reviewer.get("signed_scope") is not True:
            fail("independent engagement and signed scope are required")
    domains = set(scope.get("domains", []))
    if scope.get("completed") is not True or not REQUIRED_DOMAINS.issubset(domains):
        fail("external-review scope is incomplete")
    if not scope.get("methodology") or not scope.get("test_evidence"):
        fail("review methodology or test evidence is missing")
    if not findings:
        fail("review findings/disposition ledger must be explicit, including a zero-finding statement")
    open_critical = []
    open_high = []
    for finding in findings:
        for key in ("id", "severity", "status", "owner", "evidence"):
            if not finding.get(key):
                fail(f"finding field missing: {key}")
        severity = str(finding["severity"]).lower()
        status = str(finding["status"]).lower()
        if status in {"open", "unresolved", "in_progress"} and severity == "critical":
            open_critical.append(finding["id"])
        if status in {"open", "unresolved", "in_progress"} and severity == "high":
            open_high.append(finding["id"])
        if status in {"closed", "fixed", "not_reproducible"} and not finding.get("retest_evidence"):
            fail(f"closed finding lacks retest evidence: {finding['id']}")
        if status == "accepted_risk" and (not finding.get("risk_acceptance") or not finding.get("expiry_epoch")):
            fail(f"accepted-risk finding lacks accountable expiry: {finding['id']}")
    if open_critical or open_high:
        fail(f"unresolved critical/high findings: critical={open_critical} high={open_high}")
    if disposition.get("recommendation") != "approve" or disposition.get("production_allowed") is not True:
        fail("review disposition does not approve this exact candidate")
    if disposition.get("target_source_revision") != expected_revision or disposition.get("target_artifact_sha256") != target.get("artifact_sha256"):
        fail("review disposition is not bound to the reviewed candidate")
    if not disposition.get("residual_risk") or not disposition.get("retest_complete"):
        fail("residual risk or final retest disposition is missing")
    if data.get("production_status") != "external_security_review_qualified" and require_external:
        fail("production external-review qualification status is missing")
    limitations = data.get("limitations")
    if not isinstance(limitations, list) or not limitations:
        fail("review limitations are required")
    return data


def main() -> int:
    report = Path(os.environ.get("FAISAL_EXTERNAL_SECURITY_REVIEW", ""))
    public_key = Path(os.environ.get("FAISAL_SECURITY_REVIEW_PUBLIC_KEY", ""))
    expected = os.environ.get("FAISAL_EXPECTED_SOURCE_REV", "")
    output = Path(os.environ.get("FAISAL_EXTERNAL_SECURITY_REVIEW_REPORT", f"{report}.verification.tsv"))
    try:
        now = int(os.environ.get("FAISAL_SECURITY_REVIEW_NOW_EPOCH", str(int(time.time()))))
        max_age = int(os.environ.get("FAISAL_SECURITY_REVIEW_MAX_AGE_SECONDS", str(30 * 24 * 60 * 60)))
        data = verify(report, public_key, expected, now, max_age, require_external=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("check\tstatus\tdetail\nexternal_security_review\tpass\t" + data["reviewer"]["organization"] + "\n")
        print(f"FAISAL_EXTERNAL_SECURITY_REVIEW_OK report={output}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"check\tstatus\tdetail\nexternal_security_review\tblocked\t{exc}\n")
        print(f"FAISAL_EXTERNAL_SECURITY_REVIEW_BLOCKED reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
