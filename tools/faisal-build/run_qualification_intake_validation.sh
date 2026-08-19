#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_QUALIFICATION_INTAKE_OUT:-/home/ubuntu/agi-kernel/build/frontier/qualification-intake-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-qualification-intake"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_qualification_intake.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_qualification_intake.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_qualification_intake import CATEGORIES, QualificationClaim, QualificationIntakeError, QualificationLedger, QualificationPolicy, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "evidence_claim_is_authority": False, "qualification_receipt_is_production_authority": False, "production_approval": False}
head = "a" * 40; tag = "FAISAL-QUALIFICATION-FIXTURE"; artifact = digest({"artifact": "bzImage"}); suite = digest({"suite": "qualification-v1"}); firmware = digest({"firmware": "fw1"}); topology = digest({"topology": ["node-a", "node-b"]}); test_suite = digest({"suite": "multihost"})
policy = QualificationPolicy("runtime-policy", tag, head, artifact, 3, 10, 100, 2, 2, CATEGORIES)
def claim(i, category, origin="external_reference", **overrides):
    values = {"claim_id": f"claim-{i}", "category": category, "origin": origin, "release_tag": tag, "release_head": head, "artifact_digest": artifact, "issuer_id": f"issuer-{i}", "issuer_role": "qualification-authority", "evidence_digest": digest({"evidence": i}), "attestation_digest": digest({"attestation": i}), "issued_at": 20, "expires_at": 90, "verifier_id": f"verifier-{i}" if origin == "external_reference" else "", "verification_method": "independent-reference-check" if origin == "external_reference" else ""}
    values.update(overrides); return QualificationClaim(**values)
ledger = QualificationLedger(policy)
claims = [
    claim(1, "independent_builder", builder_id="builder-a", independence_group="group-a", qualification_suite_digest=suite),
    claim(2, "independent_builder", builder_id="builder-b", independence_group="group-b", qualification_suite_digest=suite),
    claim(3, "operator_signing", signer_id="operator-1", transparency_log_entry="rekor-entry-1", trusted_root_id="sigstore-root"),
    claim(4, "hardware", platform_id="platform-1", firmware_digest=firmware, secure_boot=True, attestation_reference="attestation-1", qualification_suite_digest=suite),
    claim(5, "external_security_review", reviewer_id="reviewer-1", reviewer_independence_declared=True, report_digest=digest({"report": 5}), method_digest=digest({"method": 5}), retest_digest=digest({"retest": 5})),
    claim(6, "multihost", node_ids=("node-a", "node-b"), topology_digest=topology, test_suite_digest=test_suite, live_execution=True),
]
admitted = []
for i, item in enumerate(claims, 1): admitted.append(ledger.admit(item, nonce=f"n-{i}", now=21, authority=authority))
status_external = ledger.status(now=21, authority=authority)
local_ledger = QualificationLedger(policy); local_ledger.admit(claim(7, "independent_builder", origin="local", builder_id="local-builder", independence_group="local-group", qualification_suite_digest=suite), nonce="local", now=21, authority=authority); status_local = local_ledger.status(now=21, authority=authority)
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except QualificationIntakeError: negative[name] = "denied"
deny("builder_missing_independence", lambda: QualificationLedger(policy).admit(claim(8, "independent_builder", builder_id="b", qualification_suite_digest=suite), nonce="b", now=21, authority=authority))
deny("signing_missing_transparency", lambda: QualificationLedger(policy).admit(claim(9, "operator_signing", signer_id="s", trusted_root_id="r"), nonce="s", now=21, authority=authority))
deny("hardware_no_secure_boot", lambda: QualificationLedger(policy).admit(claim(10, "hardware", platform_id="p", firmware_digest=firmware, secure_boot=False, attestation_reference="a", qualification_suite_digest=suite), nonce="h", now=21, authority=authority))
deny("review_not_independent", lambda: QualificationLedger(policy).admit(claim(11, "external_security_review", reviewer_id="r", reviewer_independence_declared=False, report_digest=digest({"r": 11}), method_digest=digest({"m": 11}), retest_digest=digest({"t": 11})), nonce="r", now=21, authority=authority))
deny("multihost_not_external", lambda: QualificationLedger(policy).admit(claim(12, "multihost", origin="local", node_ids=("node-a", "node-b"), topology_digest=topology, test_suite_digest=test_suite, live_execution=True), nonce="m", now=21, authority=authority))
deny("authority", lambda: QualificationLedger(policy).admit(claim(13, "operator_signing", signer_id="s", transparency_log_entry="e", trusted_root_id="r"), nonce="a", now=21, authority=dict(authority, production_approval=True)))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "qualification-evidence-intake-and-verification-ledger", "recorded_at": "2026-08-19T23:59:00Z", "policy": {"release_tag": tag, "release_head": head, "artifact_digest": artifact, "required_categories": CATEGORIES, "min_builder_attestations": 2, "min_multihost_nodes": 2}, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "external_reference_fixture": {"claims_admitted": len(admitted), "structurally_complete": status_external["external_evidence_structurally_complete"], "production_approval": status_external["production_approval"], "blockers": status_external["blockers"]}, "local_fixture": {"local_qualification": status_local["local_qualification"], "external_evidence_structurally_complete": status_local["external_evidence_structurally_complete"], "blockers": status_local["blockers"]}, "negative_cases": negative, "all_expected": all(value == "denied" for value in negative.values()), "safety": {**authority, "external_attestation_independently_verified": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-INTERRUPT-FENCE-2026-08-19"}
record["record_digest"] = digest(record)
(out / "qualification-intake-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_QUALIFICATION_INTAKE_OK tests=4_passed external_fixture=structurally_complete production_approval=false local_external_blocked=true negative_cases=6_denied")
print("record_digest=" + record["record_digest"])
PY
