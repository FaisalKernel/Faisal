#!/usr/bin/env python3
"""Validate a signed, source-bound FAISAL CVE/advisory ledger.

The ledger is deliberately stricter than a CVE-ID list. It requires exact
source binding, accountable owners, authoritative source snapshots, status
transitions, remediation or not-affected rationale, verification evidence,
and disclosure state. Model output is never an authority input.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCHEMA = "org.faisal.advisory-ledger.v2"
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
URL_RE = re.compile(r"^https://[^\s]+$")
ALLOWED_STATUS = {"fixed", "not_affected", "mitigated", "open", "under_investigation", "deferred", "disputed"}
RESOLVED_STATUS = {"fixed", "not_affected", "mitigated"}
SEVERITIES = {"unknown", "none", "low", "medium", "high", "critical"}


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read ledger JSON: {exc}")
    require(isinstance(value, dict), "ledger root must be an object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_signature(ledger: Path, signature: Path, public_key: Path) -> None:
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(ledger)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(proc.returncode == 0, "advisory ledger signature mismatch")


def as_epoch(value: Any, field: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{field} must be an integer epoch")
    require(value > 0, f"{field} must be positive")
    return value


def source_check(source: dict[str, Any], expected_revision: str, now: int, max_age: int) -> None:
    source_id = source.get("id")
    url = source.get("url")
    retrieved = as_epoch(source.get("retrieved_epoch"), f"source {source_id} retrieved_epoch")
    snapshot = source.get("snapshot_sha256")
    require(isinstance(source_id, str) and source_id, "source id missing")
    require(isinstance(url, str) and URL_RE.fullmatch(url), f"source URL invalid: {source_id}")
    require(isinstance(snapshot, str) and SHA256_RE.fullmatch(snapshot), f"source snapshot digest invalid: {source_id}")
    require(retrieved <= now, f"source retrieval is in the future: {source_id}")
    require(now - retrieved <= max_age, f"source snapshot is stale: {source_id}")
    require(source.get("authority") in {"upstream", "cisa", "nvd", "vendor", "internal"},
            f"source authority invalid: {source_id}")
    require(isinstance(source.get("coverage"), str) and source["coverage"],
            f"source coverage missing: {source_id}")
    if source.get("source_revision") is not None:
        require(source["source_revision"] == expected_revision, f"source revision mismatch: {source_id}")


def evidence_check(evidence: Any, field: str) -> None:
    require(isinstance(evidence, list) and evidence, f"{field} must contain evidence")
    for index, item in enumerate(evidence):
        require(isinstance(item, dict), f"{field}[{index}] must be an object")
        require(isinstance(item.get("type"), str) and item["type"], f"{field}[{index}] type missing")
        require(isinstance(item.get("path"), str) and item["path"], f"{field}[{index}] path missing")
        digest = item.get("sha256")
        require(isinstance(digest, str) and SHA256_RE.fullmatch(digest), f"{field}[{index}] digest invalid")


def advisory_check(item: dict[str, Any], expected_revision: str, now: int) -> str:
    advisory_id = item.get("cve_id")
    require(isinstance(advisory_id, str) and CVE_RE.fullmatch(advisory_id), f"invalid CVE identifier: {advisory_id}")
    require(item.get("source_revision") == expected_revision, f"source revision mismatch for {advisory_id}")
    status = item.get("status")
    require(status in ALLOWED_STATUS, f"invalid status for {advisory_id}: {status}")
    severity = item.get("severity")
    require(severity in SEVERITIES, f"invalid severity for {advisory_id}: {severity}")
    require(severity != "unknown", f"unknown severity for {advisory_id}")
    owner = item.get("owner")
    require(isinstance(owner, dict), f"owner missing for {advisory_id}")
    for field in ("team", "accountable_person", "contact", "escalation_contact"):
        require(isinstance(owner.get(field), str) and owner[field].strip(),
                f"owner.{field} missing for {advisory_id}")
    sources = item.get("source_urls")
    require(isinstance(sources, list) and sources, f"source_urls missing for {advisory_id}")
    for url in sources:
        require(isinstance(url, str) and URL_RE.fullmatch(url), f"invalid advisory source URL for {advisory_id}")
    reviewed = as_epoch(item.get("last_reviewed_epoch"), f"last_reviewed_epoch for {advisory_id}")
    require(reviewed <= now, f"future advisory review for {advisory_id}")
    remediation = item.get("remediation")
    verification = item.get("verification")
    disclosure = item.get("disclosure")
    require(isinstance(remediation, dict), f"remediation missing for {advisory_id}")
    require(isinstance(verification, dict), f"verification missing for {advisory_id}")
    require(isinstance(disclosure, dict), f"disclosure missing for {advisory_id}")
    require(disclosure.get("status") in {"public", "embargoed", "not_applicable"},
            f"invalid disclosure status for {advisory_id}")
    require(verification.get("status") in {"pass", "pending", "fail"},
            f"invalid verification status for {advisory_id}")
    if status == "fixed":
        commit = remediation.get("commit")
        require(isinstance(commit, str) and COMMIT_RE.fullmatch(commit), f"fix commit missing for {advisory_id}")
        require(verification.get("status") == "pass", f"fixed advisory lacks passing verification: {advisory_id}")
        evidence_check(verification.get("evidence"), f"verification.evidence for {advisory_id}")
    elif status == "not_affected":
        require(isinstance(remediation.get("rationale"), str) and remediation["rationale"].strip(),
                f"not_affected rationale missing for {advisory_id}")
        require(verification.get("status") == "pass", f"not_affected advisory lacks verification: {advisory_id}")
        evidence_check(verification.get("evidence"), f"verification.evidence for {advisory_id}")
    elif status == "mitigated":
        require(isinstance(remediation.get("mitigation"), str) and remediation["mitigation"].strip(),
                f"mitigation missing for {advisory_id}")
        require(verification.get("status") == "pass", f"mitigated advisory lacks verification: {advisory_id}")
        evidence_check(verification.get("evidence"), f"verification.evidence for {advisory_id}")
    else:
        due = as_epoch(item.get("triage_due_epoch"), f"triage_due_epoch for {advisory_id}")
        require(due >= reviewed, f"triage deadline precedes review for {advisory_id}")
        if due < now:
            fail(f"overdue unresolved advisory: {advisory_id}")
        fail(f"unresolved advisory: {advisory_id} status={status}")
    return advisory_id


def validate(ledger: Path, public_key: Path, expected_revision: str, max_age: int, now: int) -> tuple[int, list[str]]:
    require(ledger.suffix.lower() == ".json", "structured JSON advisory ledger is required")
    require(ledger.is_file(), "advisory ledger unreadable")
    signature = Path(f"{ledger}.sig")
    require(signature.is_file(), "advisory ledger signature missing")
    require(public_key.is_file(), "public key unreadable")
    verify_signature(ledger, signature, public_key)
    data = load_json(ledger)
    require(data.get("schema") == SCHEMA, "advisory ledger schema mismatch")
    require(data.get("product") == "FAISAL", "advisory ledger product mismatch")
    source = data.get("source")
    require(isinstance(source, dict), "ledger source block missing")
    require(source.get("source_revision") == expected_revision, "ledger source revision mismatch")
    require(isinstance(source.get("kernel_line"), str) and source["kernel_line"], "kernel line missing")
    reviewed = as_epoch(source.get("reviewed_epoch"), "ledger reviewed_epoch")
    require(reviewed <= now, "ledger review is in the future")
    require(now - reviewed <= max_age, "ledger review is stale")
    ownership = data.get("ownership")
    require(isinstance(ownership, dict), "ledger ownership block missing")
    for field in ("security_owner", "release_owner", "escalation_owner", "accountability_contact", "accountability_evidence_sha256"):
        require(isinstance(ownership.get(field), str) and ownership[field].strip(), f"ledger ownership.{field} missing")
    require(ownership.get("operator_confirmed") is True,
            "operator-confirmed advisory ownership is required")
    require(SHA256_RE.fullmatch(ownership["accountability_evidence_sha256"]), "ownership evidence digest invalid")
    sources = data.get("sources")
    require(isinstance(sources, list) and len(sources) >= 2, "at least two authoritative source snapshots are required")
    source_ids: set[str] = set()
    for item in sources:
        require(isinstance(item, dict), "source entry must be an object")
        source_check(item, expected_revision, now, max_age)
        require(item["id"] not in source_ids, f"duplicate source id: {item['id']}")
        source_ids.add(item["id"])
    coverage = data.get("coverage")
    require(isinstance(coverage, dict), "coverage block missing")
    require(coverage.get("complete") is True, "advisory source coverage is not complete")
    require(isinstance(coverage.get("branches"), list) and source["kernel_line"] in coverage["branches"],
            "supported kernel branch missing from coverage")
    gaps = coverage.get("unresolved_gaps")
    require(isinstance(gaps, list) and not gaps, "unresolved advisory source coverage gaps remain")
    require(coverage.get("model_output_is_authority") is False, "model output authority must be false")
    advisories = data.get("advisories")
    require(isinstance(advisories, list), "advisories must be a list")
    require(advisories or coverage.get("no_known_applicable_advisories") is True,
            "empty advisory ledger lacks an explicit reviewed-empty assertion")
    seen: set[str] = set()
    for item in advisories:
        require(isinstance(item, dict), "advisory entry must be an object")
        advisory_id = advisory_check(item, expected_revision, now)
        require(advisory_id not in seen, f"duplicate advisory: {advisory_id}")
        seen.add(advisory_id)
    decision = data.get("release_decision")
    require(isinstance(decision, dict), "release_decision block missing")
    require(decision.get("authority") != "model_output", "model output cannot authorize release")
    require(decision.get("authority") in {"security_owner", "release_owner", "joint_owner_approval"},
            "release decision authority is not an accountable owner")
    require(decision.get("status") in {"eligible_pending_other_gates", "blocked"},
            "invalid release decision status")
    return len(advisories), ["signature=pass", f"source_snapshots={len(sources)}", f"advisories={len(advisories)}"]


def main() -> int:
    ledger = Path(os.environ.get("FAISAL_ADVISORY_LEDGER", ""))
    public_key = Path(os.environ.get("FAISAL_PUBLIC_KEY", ""))
    expected = os.environ.get("FAISAL_EXPECTED_SOURCE_REV", "")
    report = Path(os.environ.get("FAISAL_ADVISORY_VERIFY_REPORT", f"{ledger}.verification.tsv"))
    max_age_raw = os.environ.get("FAISAL_ADVISORY_MAX_AGE_SECONDS", str(30 * 24 * 60 * 60))
    now_raw = os.environ.get("FAISAL_ADVISORY_NOW_EPOCH", str(int(time.time())))
    try:
        max_age = int(max_age_raw)
        now = int(now_raw)
        require(expected and COMMIT_RE.fullmatch(expected), "FAISAL_EXPECTED_SOURCE_REV must be a 40-character commit")
        require(max_age > 0, "maximum advisory age must be positive")
        count, checks = validate(ledger, public_key, expected, max_age, now)
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("check\tstatus\tdetail\n" + "\n".join(f"{c}\tpass\tverified" for c in checks) + "\n")
        print(f"FAISAL_ADVISORY_LEDGER_OK advisories={count} report={report}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(f"check\tstatus\tdetail\nledger\tblocked\t{exc}\n")
        print(f"FAISAL_ADVISORY_LEDGER_BLOCKED reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
