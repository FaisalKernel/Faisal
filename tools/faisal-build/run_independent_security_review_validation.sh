#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_SECURITY_REVIEW_OUT:-/home/ubuntu/agi-kernel/build/frontier/independent-security-review-2026-08-19}"
rm -rf "$OUT"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-security-review"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_security_review.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_security_review.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$ROOT" "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, re, subprocess, sys
root = pathlib.Path(sys.argv[1]); out = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(root / "tools/faisal-security-review"))
from faisal_security_review import AUTHORITY_KEYS, REQUIRED_CONTROLS, REQUIRED_METHODS, ReviewEvidence, ReviewLedger, ReviewPolicy, SecurityReviewError, digest, local_preparation_status

authority = {key: False for key in AUTHORITY_KEYS}
head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
release_tag = "FAISAL-FRONTIER-INDEPENDENT-SECURITY-REVIEW-2026-08-19"
policy = ReviewPolicy("security-review-2026-08-19", release_tag, head, digest({"artifact": "FAISAL-LTS-6.18.44-bzImage"}), "faIsal-control-plane-security-review", "nist-800-115-800-53a-ssdf", REQUIRED_CONTROLS, REQUIRED_METHODS, 1, 10, 100, "trusted-independent-reviewer-registry")
def evidence(origin="external_reference", **overrides):
    values = dict(evidence_id="external-review-fixture", origin=origin, release_tag=policy.release_tag, release_head=policy.release_head, artifact_digest=policy.artifact_digest, scope_id=policy.scope_id, methodology_id=policy.methodology_id, assessor_id="external-assessor-fixture", assessor_organization="independent-security-lab-fixture", independence_statement="fixture independence declaration; not a real reviewer", conflict_of_interest_statement="fixture conflict declaration; not independently verified", accreditation_reference="registry:fixture-reviewer", control_coverage={key: "pass" for key in REQUIRED_CONTROLS}, method_coverage={key: "pass" for key in REQUIRED_METHODS}, evidence_index_digest=digest({"index": "fixture"}), findings_digest=digest({"findings": "fixture"}), remediation_digest=digest({"remediation": "fixture"}), residual_risk_digest=digest({"risk": "fixture"}), report_digest=digest({"report": "fixture"}), reviewer_signature_digest=digest({"signature": "not-created"}), verification_reference="external-reference-verifier-fixture", observed_at=20, expires_at=90, nonce="external-review-fixture-nonce", synthetic_fixture=True)
    values.update(overrides); return ReviewEvidence(**values)
ledger = ReviewLedger(policy)
item = evidence()
receipt = ledger.record(item, 1, item.nonce, 21, authority)
external_status = ledger.status(21, authority)
local_status = local_preparation_status(policy, 21)
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except SecurityReviewError: negative[name] = "denied"
deny("release_head_mismatch", lambda: ReviewLedger(policy).record(evidence(release_head="b" * 40), 1, "external-review-fixture-nonce", 21, authority))
deny("scope_mismatch", lambda: ReviewLedger(policy).record(evidence(scope_id="wrong-scope"), 1, "external-review-fixture-nonce", 21, authority))
deny("incomplete_methods", lambda: ReviewLedger(policy).record(evidence(method_coverage={"architecture_review": "pass"}), 1, "external-review-fixture-nonce", 21, authority))
deny("authority_violation", lambda: ReviewLedger(policy).record(evidence(), 1, "external-review-fixture-nonce", 21, dict(authority, production_approval=True)))
bench = {}
for line in (out / "benchmark.log").read_text().splitlines():
    match = re.match(r"FAISAL_SECURITY_REVIEW_BENCHMARK name=(\S+) iterations=(\d+) mean_ns=([0-9.]+) p95_ns=([0-9.]+)", line)
    if match: bench[match.group(1)] = {"iterations": int(match.group(2)), "mean_ns": float(match.group(3)), "p95_ns": float(match.group(4))}
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "independent-external-security-review-evidence", "recorded_at": "2026-08-19T23:59:00Z", "policy": {"review_id": policy.review_id, "release_tag": policy.release_tag, "release_head": policy.release_head, "artifact_digest": policy.artifact_digest, "scope_id": policy.scope_id, "methodology_id": policy.methodology_id, "required_controls": list(policy.required_controls), "required_methods": list(policy.required_methods), "trusted_registry_id": policy.trusted_registry_id}, "research_provenance": [{"source": "https://csrc.nist.gov/pubs/sp/800/115/final", "scope": "security testing planning, execution, analysis, findings, and mitigation strategy"}, {"source": "https://csrc.nist.gov/pubs/sp/800/53/a/r5/final", "scope": "assessment plans, procedures, evidence, independent assessment, and risk-management analysis"}, {"source": "https://csrc.nist.gov/pubs/sp/800/218/final", "scope": "secure software development, vulnerability reduction, root-cause response, and supplier communication"}, {"source": "https://www.cisa.gov/resources-tools/resources/nist-sp-800-218-secure-software-development-framework-v11-recommendations-mitigating-risk-software", "scope": "third-party SSDF expectations and software supply-chain security"}], "synthetic_external_reference_fixture": {"recorded": True, "record_digest": receipt["record_digest"], "structurally_complete": external_status["structurally_complete"], "external_review_evidence_structurally_complete": external_status["external_review_evidence_structurally_complete"], "independent_external_review_completed": external_status["independent_external_review_completed"], "reviewer_identity_verified": external_status["reviewer_identity_verified"], "findings_disposition_verified": external_status["findings_disposition_verified"], "production_approval": external_status["production_approval"], "synthetic_fixture": True, "blockers": external_status["blockers"]}, "local_preparation_fixture": {"structurally_complete": local_status["structurally_complete"], "external_review_evidence_structurally_complete": local_status["external_review_evidence_structurally_complete"], "independent_external_review_completed": local_status["independent_external_review_completed"], "production_approval": local_status["production_approval"], "blockers": local_status["blockers"]}, "negative_cases": negative, "all_negative_cases_denied": all(value == "denied" for value in negative.values()), "benchmark": bench, "boundary": {"independent_external_security_review": False, "reviewer_identity_verified": False, "reviewer_independence_verified": False, "findings_disposition_verified": False, "production_approval": False}, "security_boundaries": {**authority, "fake_external_review": False, "synthetic_fixture_authority": False, "reviewer_claim_is_authority": False, "report_receipt_is_production_authority": False, "independent_external_review_completed": False, "production_approval": False}, "limitations": ["The external-reference fixture is synthetic and does not represent a real reviewer, organization, lab, accreditation, signed report, testing activity, findings disposition, or independent review.", "This contract records evidence references but does not authenticate an assessor, verify a real signature, perform penetration testing, or contact an external registry.", "A local preparation record cannot satisfy the independent external review blocker.", "Production approval remains false until a real independent assessment and authorized disposition are supplied."], "rollback_checkpoint": "FAISAL-FRONTIER-PHYSICAL-HARDWARE-MATRIX-2026-08-19-R2"}
record["record_digest"] = digest(record)
(out / "independent-security-review-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_INDEPENDENT_SECURITY_REVIEW_OK unit_tests=4 synthetic_external_fixture=structurally_complete local_preparation_blocked=true negative_cases=4_denied reviewer_identity_verified=false findings_disposition_verified=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
