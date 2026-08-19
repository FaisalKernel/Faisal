import unittest
from faisal_signing_ceremony import CeremonyEvent, CeremonyLedger, CeremonyPolicy, SigningCeremonyError, digest

AUTH = {"model_output_is_authority": False, "operator_claim_is_authority": False, "signature_receipt_is_production_authority": False, "production_approval": False}
POLICY = CeremonyPolicy("ceremony-1", "FAISAL-TEST-RELEASE", "a" * 40, digest({"artifact": "bzImage"}), "release", ("key-a", "key-b"), ("operator-a", "operator-b"), ("witness-a", "witness-b"), 2, 2, 4, 10, 100, "root-1")

def event(i, phase, **overrides):
    values = {"event_id": f"event-{i}", "phase": phase, "origin": "external_reference", "actor_id": "witness-a" if phase == "witness" else "operator-a" if phase == "sign" else "transparency-a", "actor_role": "operator" if phase == "sign" else phase, "manifest_digest": POLICY.manifest_digest, "event_digest": digest({"event": i}), "recorded_at": 20, "key_id": "", "signature_digest": "", "transparency_log_entry": "", "trusted_root_id": "", "verification_reference": "", "independence_group": "witness-group-a" if phase == "witness" else ""}
    if phase == "sign": values.update(key_id="key-a", signature_digest=digest({"signature": i}))
    if phase == "transparency": values.update(actor_id="transparency-a", key_id="key-a", signature_digest=digest({"signature": i}), transparency_log_entry="rekor-entry-a", trusted_root_id="root-1", verification_reference="external-verifier-a")
    values.update(overrides); return CeremonyEvent(**values)

class SigningCeremonyTests(unittest.TestCase):
    def test_external_threshold_ceremony_is_structurally_complete_not_approval(self):
        ledger = CeremonyLedger(POLICY)
        events = [event(1, "witness"), event(2, "witness", actor_id="witness-b", independence_group="witness-group-b"), event(3, "sign"), event(4, "sign", actor_id="operator-b", key_id="key-b", signature_digest=digest({"signature": 4})), event(5, "transparency"), event(6, "transparency", actor_id="transparency-b", key_id="key-b", signature_digest=digest({"signature": 6}), transparency_log_entry="rekor-entry-b", verification_reference="external-verifier-b")]
        for i, item in enumerate(events, 1):
            receipt = ledger.record(item, sequence=i, nonce=f"n-{i}", now=21, authority=AUTH)
            self.assertFalse(receipt["operator_ceremony_completed"]); self.assertFalse(receipt["production_approval"])
        status = ledger.status(now=21, authority=AUTH)
        self.assertTrue(status["structurally_complete"]); self.assertTrue(status["external_ceremony_evidence_structurally_complete"]); self.assertFalse(status["operator_ceremony_completed"]); self.assertFalse(status["signature_cryptographically_verified"]); self.assertIn("production_authority_not_issued", status["blockers"])

    def test_local_preparation_never_counts_as_external_ceremony(self):
        ledger = CeremonyLedger(POLICY)
        for i, phase in enumerate(("witness", "witness", "sign", "sign", "transparency", "transparency"), 1):
            overrides = {"origin": "local"}
            if phase == "witness" and i == 2: overrides.update(actor_id="witness-b", independence_group="local-witnesses")
            if phase == "sign" and i == 4: overrides.update(actor_id="operator-b", key_id="key-b", signature_digest=digest({"signature": i}))
            if phase == "transparency": overrides.update(actor_id="transparency-b" if i == 6 else "transparency-a", key_id="key-b" if i == 6 else "key-a", signature_digest=digest({"signature": i}), transparency_log_entry=f"local-log-{i}", trusted_root_id="root-1", verification_reference="local-verifier")
            ledger.record(event(i, phase, **overrides), sequence=i, nonce=f"local-{i}", now=21, authority=AUTH)
        status = ledger.status(now=21, authority=AUTH)
        self.assertTrue(status["structurally_complete"]); self.assertFalse(status["external_ceremony_evidence_structurally_complete"]); self.assertIn("external_ceremony_verification", status["blockers"])

    def test_phase_role_manifest_sequence_and_expiry_denials(self):
        cases = [
            ("manifest", event(1, "witness", manifest_digest=digest({"other": True})), 1, "m"),
            ("role", event(2, "witness", actor_id="operator-a"), 1, "r"),
            ("sign_missing", event(3, "sign", signature_digest=""), 1, "s"),
            ("transparency_root", event(4, "transparency", trusted_root_id="wrong-root"), 1, "t"),
            ("future", event(5, "witness", recorded_at=22), 1, "f"),
        ]
        for name, item, sequence, nonce in cases:
            with self.subTest(name=name), self.assertRaises(SigningCeremonyError): CeremonyLedger(POLICY).record(item, sequence=sequence, nonce=nonce, now=21, authority=AUTH)
        with self.assertRaises(SigningCeremonyError): CeremonyLedger(POLICY).record(event(1, "witness"), sequence=2, nonce="gap", now=21, authority=AUTH)

    def test_replay_authority_digest_and_manifest(self):
        ledger = CeremonyLedger(POLICY); first = ledger.record(event(1, "witness"), sequence=1, nonce="n", now=21, authority=AUTH)
        with self.assertRaises(SigningCeremonyError): ledger.record(event(1, "witness"), sequence=2, nonce="n2", now=21, authority=AUTH)
        with self.assertRaises(SigningCeremonyError): CeremonyLedger(POLICY).record(event(1, "witness"), sequence=1, nonce="a", now=21, authority=dict(AUTH, operator_claim_is_authority=True))
        self.assertTrue(first["event_digest"].startswith("sha256:")); self.assertTrue(ledger.ledger_digest().startswith("sha256:")); self.assertTrue(POLICY.manifest_digest.startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
