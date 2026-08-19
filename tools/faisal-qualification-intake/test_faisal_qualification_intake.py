import unittest
from faisal_qualification_intake import CATEGORIES, QualificationClaim, QualificationIntakeError, QualificationLedger, QualificationPolicy, digest

AUTH = {"model_output_is_authority": False, "evidence_claim_is_authority": False, "qualification_receipt_is_production_authority": False, "production_approval": False}
HEAD = "a" * 40; TAG = "FAISAL-QUALIFICATION-FIXTURE"; ARTIFACT = digest({"artifact": "bzImage"}); POLICY = QualificationPolicy("p1", TAG, HEAD, ARTIFACT, 3, 10, 100, 2, 2, CATEGORIES)
SUITE = digest({"suite": "qualification-v1"}); FIRMWARE = digest({"firmware": "fw1"}); TOPOLOGY = digest({"topology": ["node-a", "node-b"]}); TEST_SUITE = digest({"suite": "multihost"})

def claim(i, category, origin="external_reference", **overrides):
    values = {"claim_id": f"claim-{i}", "category": category, "origin": origin, "release_tag": TAG, "release_head": HEAD, "artifact_digest": ARTIFACT, "issuer_id": f"issuer-{i}", "issuer_role": "qualification-authority", "evidence_digest": digest({"evidence": i}), "attestation_digest": digest({"attestation": i}), "issued_at": 20, "expires_at": 90, "verifier_id": f"verifier-{i}" if origin == "external_reference" else "", "verification_method": "independent-reference-check" if origin == "external_reference" else ""}
    values.update(overrides); return QualificationClaim(**values)

class QualificationIntakeTests(unittest.TestCase):
    def test_external_qualification_evidence_is_structurally_complete_but_not_approval(self):
        ledger = QualificationLedger(POLICY)
        builder_a = claim(1, "independent_builder", builder_id="builder-a", independence_group="group-a", qualification_suite_digest=SUITE)
        builder_b = claim(2, "independent_builder", builder_id="builder-b", independence_group="group-b", qualification_suite_digest=SUITE)
        signing = claim(3, "operator_signing", signer_id="operator-1", transparency_log_entry="rekor-entry-1", trusted_root_id="sigstore-root")
        hardware = claim(4, "hardware", platform_id="platform-1", firmware_digest=FIRMWARE, secure_boot=True, attestation_reference="attestation-1", qualification_suite_digest=SUITE)
        review = claim(5, "external_security_review", reviewer_id="reviewer-1", reviewer_independence_declared=True, report_digest=digest({"report": 5}), method_digest=digest({"method": 5}), retest_digest=digest({"retest": 5}))
        multihost = claim(6, "multihost", node_ids=("node-a", "node-b"), topology_digest=TOPOLOGY, test_suite_digest=TEST_SUITE, live_execution=True)
        for i, item in enumerate((builder_a, builder_b, signing, hardware, review, multihost), 1):
            receipt = ledger.admit(item, nonce=f"n-{i}", now=21, authority=AUTH)
            self.assertTrue(receipt["structurally_verified"]); self.assertFalse(receipt["production_approval"])
        status = ledger.status(now=21, authority=AUTH)
        self.assertTrue(status["external_evidence_structurally_complete"]); self.assertFalse(status["production_approval"]); self.assertIn("production_authority_not_issued", status["blockers"])

    def test_local_claims_do_not_satisfy_external_blockers(self):
        ledger = QualificationLedger(POLICY)
        local = claim(1, "independent_builder", origin="local", builder_id="local-builder", independence_group="local-group", qualification_suite_digest=SUITE)
        ledger.admit(local, nonce="local", now=21, authority=AUTH)
        status = ledger.status(now=21, authority=AUTH)
        self.assertFalse(status["external_evidence_structurally_complete"]); self.assertFalse(status["local_qualification"]); self.assertIn("independent_builder", status["blockers"])

    def test_category_requirements_binding_and_freshness_denials(self):
        cases = [
            ("builder", claim(1, "independent_builder"), "b"),
            ("signing", claim(2, "operator_signing"), "s"),
            ("hardware", claim(3, "hardware", platform_id="p", firmware_digest=FIRMWARE, secure_boot=False, attestation_reference="a", qualification_suite_digest=SUITE), "h"),
            ("review", claim(4, "external_security_review", reviewer_id="r", reviewer_independence_declared=False, report_digest=digest({"r": 4}), method_digest=digest({"m": 4}), retest_digest=digest({"t": 4})), "r"),
            ("multihost", claim(5, "multihost", origin="local", node_ids=("node-a", "node-b"), topology_digest=TOPOLOGY, test_suite_digest=TEST_SUITE, live_execution=True), "m"),
            ("binding", claim(6, "hardware", release_tag="OTHER", platform_id="p", firmware_digest=FIRMWARE, secure_boot=True, attestation_reference="a", qualification_suite_digest=SUITE), "x"),
        ]
        for name, item, nonce in cases:
            with self.subTest(name=name), self.assertRaises(QualificationIntakeError): QualificationLedger(POLICY).admit(item, nonce=nonce, now=21, authority=AUTH)
        stale = claim(7, "hardware", platform_id="p", firmware_digest=FIRMWARE, secure_boot=True, attestation_reference="a", qualification_suite_digest=SUITE, issued_at=0, expires_at=20)
        with self.assertRaises(QualificationIntakeError): QualificationLedger(POLICY).admit(stale, nonce="stale", now=21, authority=AUTH)

    def test_replay_authority_and_digest(self):
        ledger = QualificationLedger(POLICY); item = claim(1, "operator_signing", signer_id="op", transparency_log_entry="entry", trusted_root_id="root")
        first = ledger.admit(item, nonce="n", now=21, authority=AUTH)
        with self.assertRaises(QualificationIntakeError): ledger.admit(item, nonce="n2", now=21, authority=AUTH)
        with self.assertRaises(QualificationIntakeError): QualificationLedger(POLICY).admit(claim(2, "operator_signing", signer_id="op", transparency_log_entry="entry", trusted_root_id="root"), nonce="a", now=21, authority=dict(AUTH, production_approval=True))
        self.assertTrue(first["claim_digest"].startswith("sha256:")); self.assertTrue(ledger.ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
