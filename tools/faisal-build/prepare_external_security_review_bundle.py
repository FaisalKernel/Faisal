#!/usr/bin/env python3
"""Prepare a reviewer-controlled, exact-candidate FAISAL security-review package."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

PACKAGE_SCHEMA = "org.faisal.external-security-review-package.v1"
REVIEW_SCHEMA = "org.faisal.external-security-review.v1"
REQUIRED_DOMAINS = [
    "kernel_uapi_and_lifecycle",
    "capability_and_provenance_security",
    "memory_scheduler_and_resource_controls",
    "replication_tls_and_trust_providers",
    "accelerator_iommu_dma_and_driver_boundaries",
    "deployment_migration_and_rollback",
    "userspace_services_and_supply_chain",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_revision(source_dir: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(source_dir), "rev-parse", "--verify", "HEAD"], text=True
    ).strip()


def copy_input(src: Path, root: Path, relative_name: str) -> dict:
    if not src.is_file():
        raise SystemExit(f"required review-package input is missing: {src}")
    destination = root / relative_name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, destination)
    return {"path": relative_name, "sha256": sha256(src), "bytes": src.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--handoff-manifest", type=Path, required=True)
    parser.add_argument("--runbook", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--reviewer-organization", default="external-reviewer-to-be-appointed")
    args = parser.parse_args()

    source_dir = args.source_dir.resolve()
    output = args.output_dir.resolve()
    if not source_dir.is_dir():
        raise SystemExit(f"source directory is missing: {source_dir}")
    actual_source_revision = git_revision(source_dir)
    package_id = f"faisal-esr-candidate-{args.source_revision[:12]}-{sha256(args.artifact)[:12]}"
    staging = output / package_id
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    files = {}
    files["kernel_artifact"] = copy_input(args.artifact, staging, "candidate/bzImage")
    files["kernel_config"] = copy_input(args.config, staging, "candidate/.config")
    files["accelerator_handoff_manifest"] = copy_input(args.handoff_manifest, staging, "candidate/physical-accelerator-handoff.json")
    files["review_runbook"] = copy_input(args.runbook, staging, "review-scope/FAISAL-EXTERNAL-SECURITY-REVIEW.md")
    files["review_validator"] = copy_input(source_dir / "tools/faisal-build/verify_external_security_review.py", staging, "review-controls/verify_external_security_review.py")
    files["review_validator_test"] = copy_input(source_dir / "tools/faisal-build/test_verify_external_security_review.py", staging, "review-controls/test_verify_external_security_review.py")
    files["release_gate"] = copy_input(source_dir / "tools/faisal-build/run_production_release_gate.sh", staging, "review-controls/run_production_release_gate.sh")
    files["program_state"] = copy_input(source_dir / "FAISAL-PROGRAM-STATE.json", staging, "project/FAISAL-PROGRAM-STATE.json")

    candidate = {
        "source_revision": args.source_revision,
        "source_worktree_revision": actual_source_revision,
        "artifact_sha256": files["kernel_artifact"]["sha256"],
        "config_sha256": files["kernel_config"]["sha256"],
        "build_id": package_id,
        "candidate_type": "linux-6.18.44-lts-forward-port",
        "model_output_is_authority": False,
    }
    package_manifest = {
        "schema": PACKAGE_SCHEMA,
        "package_id": package_id,
        "generated_epoch": int(time.time()),
        "review_status": "handoff_ready_external_execution_required",
        "candidate": candidate,
        "files": files,
        "review_contract": {
            "review_schema": REVIEW_SCHEMA,
            "evidence_class": "independent_external",
            "required_reviewer_fields": [
                "organization", "reviewer_id", "qualification_evidence", "conflict_declaration",
                "independent_of_project", "engagement_id", "signed_scope",
            ],
            "required_domains": REQUIRED_DOMAINS,
            "required_outputs": [
                "signed engagement and scope",
                "reviewer qualification and independence declaration",
                "source and artifact binding confirmation",
                "methodology and test evidence",
                "complete finding ledger, including explicit zero-finding statement when applicable",
                "remediation evidence and independent retest evidence",
                "residual-risk statement with accountable expiry",
                "signed final production disposition for this exact candidate",
            ],
            "prohibited_substitutes": [
                "project self-review",
                "same-team review",
                "model output",
                "unsigned assertions",
                "review of a different source or artifact",
                "internal scan-only evidence",
            ],
        },
        "limitations": [
            "This package is a handoff artifact and is not an external security review.",
            "The named reviewer is a placeholder until an independent qualified organization accepts the engagement.",
            "The production release gate must reject the accompanying template until an external reviewer signs a completed report.",
            "No vulnerability-free or production-security-approval claim is made.",
        ],
    }
    manifest_path = staging / "review-package.json"
    manifest_path.write_text(json.dumps(package_manifest, indent=2, sort_keys=True) + "\n")
    template = {
        "schema": REVIEW_SCHEMA,
        "evidence_class": "independent_external",
        "review_package": {
            "package_id": package_id,
            "manifest_sha256": sha256(manifest_path),
        },
        "source_revision": args.source_revision,
        "reviewed_epoch": None,
        "production_status": "pending_external_review",
        "model_output_is_authority": False,
        "target": candidate,
        "reviewer": {
            "organization": args.reviewer_organization,
            "reviewer_id": "TO_BE_FILLED_BY_EXTERNAL_REVIEWER",
            "qualification_evidence": [],
            "conflict_declaration": False,
            "independent_of_project": False,
            "engagement_id": "TO_BE_FILLED_BY_EXTERNAL_REVIEWER",
            "signed_scope": False,
        },
        "scope": {"completed": False, "domains": [], "methodology": [], "test_evidence": []},
        "findings": [],
        "disposition": {
            "recommendation": "pending",
            "production_allowed": False,
            "target_source_revision": args.source_revision,
            "target_artifact_sha256": candidate["artifact_sha256"],
            "residual_risk": "pending external review",
            "retest_complete": False,
            "signed_by_reviewer": False,
        },
        "limitations": ["template only; not a review result", "external reviewer must replace every placeholder and sign the final JSON"],
    }
    (staging / "review-evidence-template.json").write_text(json.dumps(template, indent=2, sort_keys=True) + "\n")
    readme = f"""# FAISAL Independent External Security-Review Candidate Package\n\nPackage ID: `{package_id}`\n\nThis package binds the review to source revision `{args.source_revision}`, the exact kernel artifact, configuration, and physical-accelerator handoff manifest listed in `review-package.json`. It is **not** an external review and cannot authorize production.\n\nThe external assessor must independently validate the scope, record all findings, provide remediation and retest evidence, state residual risk and expiry, and sign the completed `review-evidence-template.json` after replacing all placeholders. The FAISAL validator rejects self-review, project-affiliated reviewers, incomplete scope, wrong-candidate evidence, unresolved critical/high findings, missing retests, stale evidence, signature tampering, and model-derived authority.\n\nThe package was generated from source worktree revision `{actual_source_revision}`. That worktree identity is provenance for package generation; the reviewed candidate source revision is the explicit LTS revision in the candidate record.\n"""
    (staging / "README.md").write_text(readme)
    checksums = []
    for path in sorted(p for p in staging.rglob("*") if p.is_file()):
        checksums.append(f"{sha256(path)}  {path.relative_to(staging)}")
    (staging / "SHA256SUMS").write_text("\n".join(checksums) + "\n")

    archive = output / f"{package_id}.tar.gz"
    if archive.exists():
        archive.unlink()
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(staging, arcname=package_id)
    output_manifest = output / "review-package.json"
    shutil.copy2(manifest_path, output_manifest)
    print(f"FAISAL_EXTERNAL_SECURITY_REVIEW_PACKAGE_READY package={package_id} manifest={output_manifest} archive={archive}")
    print(f"manifest_sha256={sha256(output_manifest)} archive_sha256={sha256(archive)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
