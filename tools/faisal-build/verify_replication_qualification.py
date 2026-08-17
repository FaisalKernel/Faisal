#!/usr/bin/env python3
"""Fail-closed validator for FAISAL full TLS replication fixture evidence."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "org.faisal.full-tls-replication-fixture.v1"
REQUIRED_MARKERS = {
    "TLS_GRPC_MTLS_CERT_IDENTITY_OK",
    "QUORUM_ELECTION_TERM1_OK",
    "APPEND_ENTRIES_DURABLE_AND_QUORUM_COMMIT_OK",
    "MINORITY_PARTITION_INJECTED_OK",
    "MAJORITY_PARTITION_COMMIT_OK",
    "MINORITY_ONE_VOTE_COMMIT_DENIED_OK",
    "PARTITION_HEAL_AND_CHAIN_REPAIR_OK",
    "TAMPERED_RECORD_AND_UNDERQUORUM_CERT_DENIED_OK",
    "TLS_CLIENT_CERT_IDENTITY_MISMATCH_DENIED_OK",
    "UNTRUSTED_CA_CLIENT_DENIED_OK",
    "DURABLE_REBOOT_RESTORE_OK",
}


def fail(message: str) -> None:
    raise ValueError(message)


def verify(report: Path, public_key: Path, expected_revision: str, now: int, max_age: int) -> dict:
    if report.suffix != ".json":
        fail("structured JSON replication evidence is required")
    signature = Path(f"{report}.sig")
    if not report.is_file() or not signature.is_file() or not public_key.is_file():
        fail("replication evidence, detached signature, and public key are required")
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(report)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail("replication evidence signature mismatch")
    data = json.loads(report.read_text())
    if data.get("schema") != SCHEMA:
        fail("replication schema mismatch")
    if data.get("status") != "pass_software_fixture_physical_and_production_pkI_pending":
        fail("replication fixture did not pass with bounded status")
    if data.get("source_revision") != expected_revision:
        fail("replication source revision mismatch")
    reviewed = data.get("reviewed_epoch")
    if not isinstance(reviewed, int) or reviewed > now or now - reviewed > max_age:
        fail("replication evidence is stale or has invalid timestamp")
    markers = set(data.get("markers", []))
    missing = sorted(REQUIRED_MARKERS - markers)
    if missing:
        fail("replication markers missing: " + ",".join(missing))
    if data.get("transport") != "gRPC_TLS_mutual_authentication":
        fail("gRPC mutual TLS transport claim missing")
    if data.get("authenticated_quorum_certificate") is not True:
        fail("authenticated quorum certificate evidence missing")
    if data.get("minority_partition_commit_denied") is not True:
        fail("minority partition safety evidence missing")
    if data.get("durable_state_reload") is not True:
        fail("durable state reload evidence missing")
    limitations = data.get("limitations")
    if not isinstance(limitations, list) or not limitations:
        fail("explicit replication qualification limitations are required")
    if "physical" not in data.get("status", "").lower() or "pending" not in data.get("status", "").lower():
        fail("replication evidence must explicitly retain physical/production limitations")
    if data.get("model_output_is_authority", False) is not False:
        fail("model output cannot be replication authority")
    return data


def main() -> int:
    report = Path(os.environ.get("FAISAL_REPLICATION_EVIDENCE", ""))
    public_key = Path(os.environ.get("FAISAL_PUBLIC_KEY", ""))
    expected = os.environ.get("FAISAL_EXPECTED_SOURCE_REV", "")
    output = Path(os.environ.get("FAISAL_REPLICATION_VERIFY_REPORT", f"{report}.verification.tsv"))
    try:
        now = int(os.environ.get("FAISAL_REPLICATION_NOW_EPOCH", str(int(time.time()))))
        max_age = int(os.environ.get("FAISAL_REPLICATION_MAX_AGE_SECONDS", str(30 * 24 * 60 * 60)))
        data = verify(report, public_key, expected, now, max_age)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("check\tstatus\tdetail\nreplication_fixture\tpass\t" + str(len(data["markers"])) + " markers\n")
        print(f"FAISAL_REPLICATION_QUALIFICATION_OK report={output}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"check\tstatus\tdetail\nreplication_fixture\tblocked\t{exc}\n")
        print(f"FAISAL_REPLICATION_QUALIFICATION_BLOCKED reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
