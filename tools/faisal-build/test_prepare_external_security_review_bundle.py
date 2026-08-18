#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
from pathlib import Path

import verify_external_security_review as validator

ROOT = Path(__file__).parents[2]
LTS_REVISION = "105f2b85e4c26305a79f5e584df6ebb705858d33"
LTS_BUILD = Path("/home/ubuntu/agi-kernel/build/faisal-lts-6.18.44")
HANDOFF = Path("/home/ubuntu/agi-kernel/build/m175-physical-accelerator/physical-accelerator-handoff.json")
NOW = 1801000000


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="faisal-esr-package-") as raw:
        directory = Path(raw)
        output = directory / "package"
        command = [
            "python3", str(ROOT / "tools/faisal-build/prepare_external_security_review_bundle.py"),
            "--source-dir", str(ROOT),
            "--source-revision", LTS_REVISION,
            "--artifact", str(LTS_BUILD / "arch/x86/boot/bzImage"),
            "--config", str(LTS_BUILD / ".config"),
            "--handoff-manifest", str(HANDOFF),
            "--runbook", str(ROOT / "FAISAL-EXTERNAL-SECURITY-REVIEW.md"),
            "--output-dir", str(output),
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr
        package = output / "review-package.json"
        package_data = json.loads(package.read_text())
        template_path = output / package_data["package_id"] / "review-evidence-template.json"
        report_data = json.loads(template_path.read_text())

        private = directory / "reviewer-private.pem"
        public = directory / "reviewer-public.pem"
        report = directory / "completed-review.json"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        report_data["reviewed_epoch"] = NOW
        report_data["production_status"] = "external_security_review_qualified"
        reviewer = report_data["reviewer"]
        reviewer.update({
            "organization": "Independent Security Review Group",
            "reviewer_id": "reviewer-m176-01",
            "qualification_evidence": ["signed-certification-record", "engagement-scope"],
            "conflict_declaration": True,
            "independent_of_project": True,
            "engagement_id": "engagement-FAISAL-M176",
            "signed_scope": True,
            "public_key_sha256": validator.sha256_file(public),
            "signed_final_report": True,
        })
        report_data["scope"] = {
            "completed": True,
            "domains": sorted(validator.REQUIRED_DOMAINS),
            "methodology": ["source review", "threat modeling", "fuzz review", "negative-path review"],
            "test_evidence": ["signed-test-matrix", "reproduction-records", "retest-records"],
        }
        report_data["findings"] = [{
            "id": "ESR-M176-0000",
            "severity": "informational",
            "status": "closed",
            "owner": "external-reviewer",
            "evidence": "signed-no-critical-high-findings-statement",
            "retest_evidence": "signed-retest-ESR-M176-0000",
        }]
        disposition = report_data["disposition"]
        disposition.update({
            "recommendation": "approve",
            "production_allowed": True,
            "residual_risk": "Documented residual risks accepted only for this exact candidate.",
            "retest_complete": True,
            "signed_by_reviewer": True,
        })
        report.write_text(json.dumps(report_data, indent=2, sort_keys=True) + "\n")
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", f"{report}.sig", str(report)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        accepted = validator.verify(report, public, LTS_REVISION, NOW, 3600, package=package)
        assert accepted["review_package"]["package_id"] == package_data["package_id"]

        tampered_package = json.loads(package.read_text())
        tampered_package["candidate"]["artifact_sha256"] = "f" * 64
        package.write_text(json.dumps(tampered_package, indent=2, sort_keys=True) + "\n")
        try:
            validator.verify(report, public, LTS_REVISION, NOW, 3600, package=package)
        except ValueError:
            pass
        else:
            raise AssertionError("tampered exact-candidate package was accepted")

    print("FAISAL_EXTERNAL_SECURITY_REVIEW_PACKAGE_TEST_OK exact_candidate_key_binding_signed_disposition_package_tamper_denied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
