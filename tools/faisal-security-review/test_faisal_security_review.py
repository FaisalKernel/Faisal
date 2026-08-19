#!/usr/bin/env python3
from __future__ import annotations

import unittest
from faisal_security_review import (
    AUTHORITY_KEYS, REQUIRED_CONTROLS, REQUIRED_METHODS, ReviewEvidence, ReviewLedger, ReviewPolicy, SecurityReviewError, digest, local_preparation_status,
)

AUTH = {key: False for key in AUTHORITY_KEYS}
POLICY = ReviewPolicy("review-1", "FAISAL-SECURITY-REVIEW-TEST", "a" * 40, digest({"artifact": "fixture"}), "scope-1", "nist-800-115-800-53a-ssdf", REQUIRED_CONTROLS, REQUIRED_METHODS, 1, 10, 100, "trusted-reviewer-registry")

def evidence(origin="external_reference", **overrides):
    values = dict(
        evidence_id="review-1", origin=origin, release_tag=POLICY.release_tag, release_head=POLICY.release_head, artifact_digest=POLICY.artifact_digest,
        scope_id=POLICY.scope_id, methodology_id=POLICY.methodology_id, assessor_id="assessor-1", assessor_organization="independent-lab-1",
        independence_statement="no financial, operational, or authorship conflict", conflict_of_interest_statement="no conflict declared", accreditation_reference="registry:lab-1",
        control_coverage={control: "pass" for control in REQUIRED_CONTROLS}, method_coverage={method: "pass" for method in REQUIRED_METHODS},
        evidence_index_digest=digest({"index": 1}), findings_digest=digest({"findings": 1}), remediation_digest=digest({"remediation": 1}), residual_risk_digest=digest({"risk": 1}), report_digest=digest({"report": 1}), reviewer_signature_digest=digest({"signature": 1}),
        verification_reference="external-verifier-1", observed_at=20, expires_at=90, nonce="nonce-1", synthetic_fixture=True,
    )
    values.update(overrides)
    return ReviewEvidence(**values)

class SecurityReviewTests(unittest.TestCase):
    def test_complete_external_review_is_structural_only_not_completion(self):
        ledger = ReviewLedger(POLICY)
        item = evidence()
        ledger.record(item, 1, item.nonce, 21, AUTH)
        status = ledger.status(21, AUTH)
        self.assertTrue(status["structurally_complete"])
        self.assertTrue(status["external_review_evidence_structurally_complete"])
        self.assertFalse(status["independent_external_review_completed"])
        self.assertFalse(status["reviewer_identity_verified"])
        self.assertFalse(status["findings_disposition_verified"])
        self.assertFalse(status["production_approval"])

    def test_local_preparation_never_counts_as_external_review(self):
        status = local_preparation_status(POLICY, 21)
        self.assertTrue(status["structurally_complete"])
        self.assertFalse(status["external_review_evidence_structurally_complete"])
        self.assertFalse(status["independent_external_review_completed"])
        self.assertIn("independent_external_assessment", status["blockers"])

    def test_scope_assessor_method_and_authority_denials(self):
        with self.assertRaises(SecurityReviewError):
            ReviewLedger(POLICY).record(evidence(release_head="b" * 40), 1, "nonce-1", 21, AUTH)
        with self.assertRaises(SecurityReviewError):
            ReviewLedger(POLICY).record(evidence(assessor_id=""), 1, "nonce-1", 21, AUTH)
        with self.assertRaises(SecurityReviewError):
            ReviewLedger(POLICY).record(evidence(method_coverage={"architecture_review": "pass"}), 1, "nonce-1", 21, AUTH)
        with self.assertRaises(SecurityReviewError):
            ReviewLedger(POLICY).record(evidence(), 1, "nonce-1", 21, dict(AUTH, production_approval=True))

    def test_replay_and_sequence_denials(self):
        ledger = ReviewLedger(POLICY)
        first = evidence()
        ledger.record(first, 1, first.nonce, 21, AUTH)
        with self.assertRaises(SecurityReviewError):
            ledger.record(evidence(evidence_id="review-2", nonce=first.nonce), 2, first.nonce, 21, AUTH)
        with self.assertRaises(SecurityReviewError):
            ledger.record(evidence(evidence_id="review-3", nonce="nonce-3"), 3, "nonce-3", 21, AUTH)

if __name__ == "__main__":
    unittest.main(verbosity=2)
