#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import verify_external_security_review as validator

REVISION = "5" * 40
NOW = 1801000000
DOMAINS = sorted(validator.REQUIRED_DOMAINS)


def good() -> dict:
    target = {
        "source_revision": REVISION,
        "artifact_sha256": "a" * 64,
        "build_id": "faisal-review-candidate-173",
    }
    return {
        "schema": validator.SCHEMA,
        "evidence_class": "independent_external",
        "source_revision": REVISION,
        "reviewed_epoch": NOW,
        "production_status": "external_security_review_qualified",
        "model_output_is_authority": False,
        "target": target,
        "reviewer": {
            "organization": "Independent Security Review Group",
            "reviewer_id": "reviewer-173-01",
            "public_key_sha256": "TO_BE_BOUND_AFTER_KEY_GENERATION",
            "signed_final_report": True,
            "affiliation": "external-security-review-group",
            "qualification_evidence": ["signed-certification-record", "engagement-scope"],
            "conflict_declaration": True,
            "independent_of_project": True,
            "engagement_id": "engagement-FAISAL-173",
            "signed_scope": True,
        },
        "scope": {
            "completed": True,
            "domains": DOMAINS,
            "methodology": ["source review", "threat modeling", "fuzz review", "negative-path review"],
            "test_evidence": ["signed-test-matrix", "reproduction-records", "retest-records"],
        },
        "findings": [{
            "id": "ESR-0000",
            "severity": "informational",
            "status": "closed",
            "owner": "external-reviewer",
            "evidence": "signed-no-critical-high-findings-statement",
            "retest_evidence": "signed-retest-ESR-0000",
        }],
        "disposition": {
            "recommendation": "approve",
            "production_allowed": True,
            "target_source_revision": REVISION,
            "target_artifact_sha256": target["artifact_sha256"],
            "residual_risk": "Documented residual risks accepted only for this exact candidate.",
            "retest_complete": True,
            "signed_by_reviewer": True,
        },
        "limitations": ["review applies only to the exact source, artifact, and evidence set"],
    }


def signed(directory: Path, data: dict) -> tuple[Path, Path]:
    private = directory / "private.pem"
    public = directory / "public.pem"
    report = directory / "review.json"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    data["reviewer"]["public_key_sha256"] = validator.sha256_file(public)
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
    with tempfile.TemporaryDirectory(prefix="faisal-external-review-") as raw:
        directory = Path(raw)
        report, public = signed(directory, good())
        assert validator.verify(report, public, REVISION, NOW, 3600)["production_status"] == "external_security_review_qualified"
        cli_report = directory / "verification.tsv"
        env = os.environ.copy()
        env.update({
            "FAISAL_EXTERNAL_SECURITY_REVIEW": str(report),
            "FAISAL_SECURITY_REVIEW_PUBLIC_KEY": str(public),
            "FAISAL_EXPECTED_SOURCE_REV": REVISION,
            "FAISAL_SECURITY_REVIEW_NOW_EPOCH": str(NOW),
            "FAISAL_EXTERNAL_SECURITY_REVIEW_REPORT": str(cli_report),
        })
        cli = subprocess.run(["python3", "tools/faisal-build/verify_external_security_review.py"], cwd=Path(__file__).parents[2], env=env, capture_output=True, text=True, check=False)
        assert cli.returncode == 0 and "FAISAL_EXTERNAL_SECURITY_REVIEW_OK" in cli.stdout
        assert cli_report.is_file()

        self_review = good()
        self_review["reviewer"]["independent_of_project"] = False
        expect_failure(directory, self_review, "self-review")

        incomplete_scope = good()
        incomplete_scope["scope"]["domains"] = DOMAINS[:-1]
        expect_failure(directory, incomplete_scope, "incomplete scope")

        open_high = good()
        open_high["findings"] = [{"id": "ESR-0001", "severity": "high", "status": "open", "owner": "owner", "evidence": "finding"}]
        expect_failure(directory, open_high, "open high finding")

        wrong_target = good()
        wrong_target["disposition"]["target_source_revision"] = "6" * 40
        expect_failure(directory, wrong_target, "disposition target mismatch")

        stale = good()
        stale["reviewed_epoch"] = NOW - 3601
        expect_failure(directory, stale, "stale report")

        model_authority = good()
        model_authority["model_output_is_authority"] = True
        expect_failure(directory, model_authority, "model authority")

        report.write_text(report.read_text().replace("reviewer-173-01", "tampered-reviewer"))
        try:
            validator.verify(report, public, REVISION, NOW, 3600)
        except ValueError:
            pass
        else:
            raise AssertionError("signature tampering accepted")
    print("FAISAL_EXTERNAL_SECURITY_REVIEW_TEST_OK independence_scope_findings_disposition_stale_tamper_denied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
