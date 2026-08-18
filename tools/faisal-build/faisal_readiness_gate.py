#!/usr/bin/env python3
"""Fail-closed final FAISAL readiness gate.

The gate distinguishes local qualification from production approval. It never
promotes a candidate based on model output, provider metadata, or compilation
alone. Production mode requires all explicitly external qualifications.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PROTECTED = {
    "M63-COMPUTE-CONTEXT-DESIGN.md",
    "M63-SECURITY-REVIEW.md",
    "tools/faisal-build/evidence/upstream-kernel-release-research-2026-08-17.txt",
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON object required: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(repo: Path, *args: str) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"git command failed: {exc}")
    return ""


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def check_candidate(repo: Path, candidate: Path, state: Path, evidence: Path,
                    provenance: Path, expected_tag: str | None) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    manifest = load_json(candidate)
    program = load_json(state)
    record = load_json(evidence)
    prov = load_json(provenance)
    require(manifest.get("schema") == "org.faisal.production-candidate.v1", "candidate schema")
    require(manifest.get("status") == "bounded_candidate_not_production_approved", "candidate status is not bounded")
    require(manifest.get("repository_head") == git(repo, "rev-parse", "HEAD"), "candidate head mismatch")
    require(prov.get("repository_head") == manifest.get("repository_head"), "provenance head mismatch")
    state_head = program.get("current_head")
    head = git(repo, "rev-parse", "HEAD")
    require(isinstance(state_head, str) and len(state_head) == 40, "program state head malformed")
    require(state_head == manifest.get("repository_head") or git(repo, "merge-base", "--is-ancestor", state_head, head) == "", "program state head outside bounded candidate")
    distance = int(git(repo, "rev-list", "--count", f"{state_head}..{head}"))
    require(distance <= 3, "program state head exceeds bounded ancestry window")
    if expected_tag:
        tag_commit = git(repo, "rev-parse", f"{expected_tag}^{{commit}}")
        require(tag_commit == git(repo, "rev-parse", "HEAD"), "tag does not resolve to HEAD")
        require(program.get("current_tag") == expected_tag, "program state tag mismatch")
    require(isinstance(program.get("current_abi"), int) and program["current_abi"] >= 46, "platform ABI is below M247")
    approval = manifest.get("approval", {})
    require(approval.get("status") == "blocked", "candidate approval is not blocked")
    require(approval.get("operator_approved") is False, "operator approval must be false")
    require(approval.get("model_output_is_authority") is False, "model authority boundary missing")
    require(approval.get("signature_present") is False, "local candidate must not claim release signature")
    boundary = record.get("boundary", {})
    require(boundary.get("production_approval") is False, "evidence production boundary missing")
    security = record.get("security_boundaries", {})
    for key in ("model_output_is_authority", "optimizer_output_is_authority", "provider_metadata_is_authority", "unrestricted_kernel_self_modification", "fake_hardware_evidence", "fake_external_review", "production_approval"):
        if key in security:
            require(security[key] is False, f"security boundary {key} is not false")
    evidence_paths = {item.get("path") for item in manifest.get("evidence_index", []) if isinstance(item, dict)}
    require(str(evidence.relative_to(repo)) in evidence_paths, "final evidence is not indexed")
    require(sha256_file(evidence) == next(item.get("sha256") for item in manifest["evidence_index"] if item.get("path") == str(evidence.relative_to(repo))), "final evidence hash mismatch")
    checks.extend([
        {"name": "candidate_schema", "status": "pass"},
        {"name": "candidate_provenance_binding", "status": "pass"},
        {"name": "program_state_binding", "status": "pass"},
        {"name": "tag_binding", "status": "pass" if expected_tag else "not-requested"},
        {"name": "non_authority_boundaries", "status": "pass"},
        {"name": "evidence_index_hash", "status": "pass"},
    ])
    return checks


def check_protected(repo: Path) -> dict[str, str]:
    staged = git(repo, "diff", "--cached", "--name-only").splitlines()
    forbidden = sorted(set(staged) & PROTECTED)
    require(not forbidden, f"protected files staged: {forbidden}")
    return {"name": "protected_files_not_staged", "status": "pass"}


def check_docs(repo: Path) -> list[dict[str, str]]:
    required = [
        "AGI-KERNEL-ROADMAP.md",
        "AGI-KERNEL-ARCHITECTURE.md",
        "AGI-KERNEL-DESIGN-DECISIONS.md",
        "AGI-KERNEL-READINESS-GATE.md",
        "AGI-KERNEL-RELEASE-MAINTENANCE.md",
    ]
    for name in required:
        path = repo / name
        require(path.is_file() and path.stat().st_size > 0, f"required document missing: {name}")
    return [{"name": f"document:{name}", "status": "pass"} for name in required]


def check_logs(logs: list[Path]) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    marker = re.compile(r"(?:EXIT=0|VALIDATION_OK|QEMU_VALIDATION_OK|SOAK_OK|LOCAL_PREFLIGHT_OK|_OK(?:\s|$))")
    for path in logs:
        require(path.is_file() and path.stat().st_size > 0, f"validation log missing: {path}")
        text = path.read_text(errors="replace")
        require(marker.search(text) is not None, f"no passing marker in validation log: {path}")
        checks.append({"name": f"validation_log:{path.name}", "status": "pass"})
    require(bool(logs), "no validation logs supplied")
    return checks


def external_blockers(record: dict[str, Any]) -> list[str]:
    boundary = record.get("boundary", {})
    return sorted(key for key, value in boundary.items() if value is False and key not in {"production_approval"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-tag")
    parser.add_argument("--mode", choices=("local", "production"), default="local")
    parser.add_argument("--log", action="append", type=Path, default=[])
    args = parser.parse_args()
    result: dict[str, Any] = {
        "schema": "org.faisal.agi-kernel-readiness.v1",
        "project": "FAISAL",
        "mode": args.mode,
        "repository_head": git(args.repo, "rev-parse", "HEAD"),
        "checks": [],
        "claims_not_made": ["AGI", "production approval", "physical hardware qualification", "independent external review"],
        "authority_boundaries": {
            "model_output_is_authority": False,
            "optimizer_output_is_authority": False,
            "provider_metadata_is_authority": False,
            "unrestricted_kernel_self_modification": False,
        },
    }
    try:
        result["checks"].extend(check_candidate(args.repo, args.candidate, args.state, args.evidence, args.provenance, args.expected_tag))
        result["checks"].append(check_protected(args.repo))
        result["checks"].extend(check_docs(args.repo))
        result["checks"].extend(check_logs(args.log))
        record = load_json(args.evidence)
        blockers = external_blockers(record)
        result["external_blockers"] = blockers
        if args.mode == "production":
            require(not blockers, f"production blockers remain: {blockers}")
            require(record.get("boundary", {}).get("production_approval") is True, "production approval evidence is absent")
        result["status"] = "production_qualified" if args.mode == "production" else "local_qualification_passed_release_blocked"
        result["production_approval"] = args.mode == "production"
        result["check_count"] = len(result["checks"])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"FAISAL_READINESS_GATE_OK mode={args.mode} checks={result['check_count']} blockers={len(blockers)}")
        return 0
    except (RuntimeError, StopIteration) as exc:
        result["status"] = "blocked"
        result["production_approval"] = False
        result["failure"] = str(exc)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"FAISAL_READINESS_GATE_BLOCKED mode={args.mode} reason={exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
