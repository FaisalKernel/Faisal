#!/usr/bin/env python3
"""Regression tests for the FAISAL structured advisory ledger.

The CVE identifiers and evidence paths are synthetic fixtures only. They do not
assert that those identifiers describe real vulnerabilities.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import verify_advisory_ledger as validator

REVISION = "1" * 40
NOW = 1800000000


def keypair(directory: Path) -> tuple[Path, Path]:
    private = directory / "private.pem"
    public = directory / "public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return private, public


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def base_ledger() -> dict:
    return {
        "schema": validator.SCHEMA,
        "product": "FAISAL",
        "source": {
            "kernel_line": "Linux 6.18.44 LTS",
            "source_revision": REVISION,
            "reviewed_epoch": NOW,
        },
        "ownership": {
            "security_owner": "security-team",
            "release_owner": "release-engineering",
            "escalation_owner": "incident-commander",
            "accountability_contact": "security@example.invalid",
            "accountability_evidence_sha256": digest("ownership"),
            "operator_confirmed": True,
        },
        "sources": [
            {
                "id": "kernel-cve-process",
                "authority": "upstream",
                "url": "https://docs.kernel.org/process/cve.html",
                "retrieved_epoch": NOW,
                "snapshot_sha256": digest("kernel-cve-process"),
                "coverage": "upstream Linux CVE assignment and supported branches",
                "source_revision": REVISION,
            },
            {
                "id": "cisa-kev",
                "authority": "cisa",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "retrieved_epoch": NOW,
                "snapshot_sha256": digest("cisa-kev"),
                "coverage": "known exploited vulnerability cross-check",
            },
        ],
        "coverage": {
            "complete": True,
            "branches": ["Linux 6.18.44 LTS"],
            "unresolved_gaps": [],
            "no_known_applicable_advisories": False,
            "model_output_is_authority": False,
        },
        "advisories": [
            {
                "cve_id": "CVE-2099-00001",
                "status": "fixed",
                "severity": "high",
                "source_revision": REVISION,
                "owner": {
                    "team": "kernel-security",
                    "accountable_person": "owner-a",
                    "contact": "owner-a@example.invalid",
                    "escalation_contact": "incident@example.invalid",
                },
                "source_urls": ["https://docs.kernel.org/process/cve.html"],
                "last_reviewed_epoch": NOW,
                "remediation": {"commit": "2" * 40},
                "verification": {
                    "status": "pass",
                    "evidence": [{"type": "test-log", "path": "synthetic-fixed.log", "sha256": digest("fixed")}],
                },
                "disclosure": {"status": "public", "reference": "synthetic"},
            },
            {
                "cve_id": "CVE-2099-00002",
                "status": "not_affected",
                "severity": "medium",
                "source_revision": REVISION,
                "owner": {
                    "team": "kernel-security",
                    "accountable_person": "owner-b",
                    "contact": "owner-b@example.invalid",
                    "escalation_contact": "incident@example.invalid",
                },
                "source_urls": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
                "last_reviewed_epoch": NOW,
                "remediation": {"rationale": "synthetic fixture only"},
                "verification": {
                    "status": "pass",
                    "evidence": [{"type": "analysis", "path": "synthetic-na.log", "sha256": digest("na")}],
                },
                "disclosure": {"status": "not_applicable", "reference": "synthetic"},
            },
        ],
        "release_decision": {
            "authority": "joint_owner_approval",
            "status": "blocked",
            "reason": "synthetic fixture; other production gates remain",
        },
    }


def signed_ledger(directory: Path, data: dict, private: Path) -> tuple[Path, Path]:
    ledger = directory / "ledger.json"
    signature = Path(f"{ledger}.sig")
    ledger.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(ledger)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return ledger, signature


def expect_failure(data: dict, private: Path, public: Path, directory: Path, label: str) -> None:
    ledger, _ = signed_ledger(directory, data, private)
    try:
        validator.validate(ledger, public, REVISION, 30 * 24 * 60 * 60, NOW)
    except ValueError:
        return
    raise AssertionError(f"expected failure: {label}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="faisal-advisory-test-") as raw:
        directory = Path(raw)
        private, public = keypair(directory)
        good = base_ledger()
        ledger, signature = signed_ledger(directory, good, private)
        count, checks = validator.validate(ledger, public, REVISION, 30 * 24 * 60 * 60, NOW)
        assert count == 2 and len(checks) == 3
        cli_report = directory / "cli-verification.tsv"
        cli_env = os.environ.copy()
        cli_env.update({
            "FAISAL_ADVISORY_LEDGER": str(ledger),
            "FAISAL_PUBLIC_KEY": str(public),
            "FAISAL_EXPECTED_SOURCE_REV": REVISION,
            "FAISAL_ADVISORY_NOW_EPOCH": str(NOW),
            "FAISAL_ADVISORY_VERIFY_REPORT": str(cli_report),
        })
        cli = subprocess.run([sys.executable, str(Path(__file__).with_name("verify_advisory_ledger.py"))], env=cli_env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        assert cli.returncode == 0 and "FAISAL_ADVISORY_LEDGER_OK" in cli.stdout
        assert "signature=pass\tpass" in cli_report.read_text()
        shell_cli = subprocess.run([str(Path(__file__).with_name("verify_advisory_ledger.sh"))], env=cli_env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        assert shell_cli.returncode == 0 and "FAISAL_ADVISORY_LEDGER_OK" in shell_cli.stdout

        missing_owner = json.loads(json.dumps(good))
        del missing_owner["advisories"][0]["owner"]["accountable_person"]
        expect_failure(missing_owner, private, public, directory, "missing owner")

        unresolved = json.loads(json.dumps(good))
        unresolved["advisories"][0]["status"] = "open"
        unresolved["advisories"][0]["triage_due_epoch"] = NOW + 3600
        expect_failure(unresolved, private, public, directory, "open advisory")

        stale = json.loads(json.dumps(good))
        stale["sources"][0]["retrieved_epoch"] = NOW - 31 * 24 * 60 * 60
        expect_failure(stale, private, public, directory, "stale source")

        model_authority = json.loads(json.dumps(good))
        model_authority["coverage"]["model_output_is_authority"] = True
        expect_failure(model_authority, private, public, directory, "model authority")

        tampered = json.loads(ledger.read_text())
        tampered["advisories"][0]["severity"] = "critical"
        ledger.write_text(json.dumps(tampered))
        try:
            validator.verify_signature(ledger, signature, public)
        except ValueError:
            pass
        else:
            raise AssertionError("tampered signature was accepted")

    print("FAISAL_ADVISORY_VERIFIER_TEST_OK valid_fixed_not_affected_stale_owner_unresolved_model_authority_tamper")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
