#!/usr/bin/env python3
from __future__ import annotations

import statistics
import time

from faisal_security_review import AUTHORITY_KEYS, REQUIRED_CONTROLS, REQUIRED_METHODS, ReviewEvidence, ReviewLedger, ReviewPolicy, digest

ITERATIONS = 1000
AUTH = {key: False for key in AUTHORITY_KEYS}
POLICY = ReviewPolicy("review-bench", "FAISAL-SECURITY-REVIEW-BENCH", "a" * 40, digest({"artifact": "fixture"}), "scope-bench", "nist-methodology", REQUIRED_CONTROLS, REQUIRED_METHODS, 1, 10, 100, "registry-bench")

def evidence():
    return ReviewEvidence(
        evidence_id="review-bench", origin="external_reference", release_tag=POLICY.release_tag, release_head=POLICY.release_head, artifact_digest=POLICY.artifact_digest, scope_id=POLICY.scope_id, methodology_id=POLICY.methodology_id,
        assessor_id="assessor-bench", assessor_organization="lab-bench", independence_statement="independent", conflict_of_interest_statement="none", accreditation_reference="registry:bench",
        control_coverage={key: "pass" for key in REQUIRED_CONTROLS}, method_coverage={key: "pass" for key in REQUIRED_METHODS}, evidence_index_digest=digest({"index": 1}), findings_digest=digest({"findings": 1}), remediation_digest=digest({"remediation": 1}), residual_risk_digest=digest({"risk": 1}), report_digest=digest({"report": 1}), reviewer_signature_digest=digest({"signature": 1}), verification_reference="verifier-bench", observed_at=20, expires_at=90, nonce="nonce-bench", synthetic_fixture=True,
    )

def baseline():
    return digest({"release": POLICY.release_tag, "head": POLICY.release_head, "scope": POLICY.scope_id})

def admission():
    ledger = ReviewLedger(POLICY); item = evidence(); ledger.record(item, 1, item.nonce, 21, AUTH)

def status():
    ledger = ReviewLedger(POLICY); item = evidence(); ledger.record(item, 1, item.nonce, 21, AUTH); ledger.status(21, AUTH)

def sample(fn):
    values = []
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(ITERATIONS * .95) - 1]

for name, fn in (("baseline_manifest_digest", baseline), ("review_evidence_admission", admission), ("review_status_evaluation", status)):
    mean, p95 = sample(fn)
    print(f"FAISAL_SECURITY_REVIEW_BENCHMARK name={name} iterations={ITERATIONS} mean_ns={mean:.2f} p95_ns={p95:.2f}")
print("FAISAL_SECURITY_REVIEW_BENCHMARK_SCOPE=local_structural_review_contract_without_real_assessor_identity_signature_or_external_testing")
