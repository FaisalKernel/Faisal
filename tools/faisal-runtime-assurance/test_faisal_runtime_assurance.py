import unittest
from faisal_runtime_assurance import AssuranceEnvelope, RuntimeAssuranceError, RuntimeAssuranceLedger, RuntimeObservation, digest

AUTH = {"model_output_is_authority": False, "observation_is_authority": False, "tool_result_is_authority": False, "assurance_receipt_is_execution_authority": False, "assurance_receipt_is_production_authority": False}

def surface(name="surface"):
    return digest({"surface": name})

def envelope(surface_digest=None):
    return AssuranceEnvelope("env-1", "policy-1", surface_digest or surface(), 7, 10, 100, 20, 10, (("cpu", 80),), (("cpu", 100),), frozenset(("continue", "restrict", "quarantine", "terminate")))

def obs(seq, prev="genesis", cpu=20, at=20, surf=None):
    evidence = digest({"seq": seq, "cpu": cpu})
    return RuntimeObservation(f"obs-{seq}", "workload-1", surf or surface(), seq, at, prev, (("cpu", cpu),), evidence)

class RuntimeAssuranceTests(unittest.TestCase):
    def test_continue_restrict_quarantine_terminate(self):
        l = RuntimeAssuranceLedger(envelope())
        a = l.decide(obs(1), 21, "n1", AUTH); self.assertEqual(a["action"], "continue")
        b = l.decide(obs(2, a["decision_digest"], cpu=90), 22, "n2", AUTH); self.assertEqual(b["action"], "restrict")
        c = l.decide(obs(3, b["decision_digest"], cpu=20, at=0), 30, "n3", AUTH); self.assertEqual(c["action"], "quarantine")
        d = l.decide(obs(4, c["decision_digest"], cpu=101), 31, "n4", AUTH); self.assertEqual(d["action"], "terminate")
        self.assertFalse(d["execution_performed"]); self.assertFalse(d["production_approved"])

    def test_missing_metric_and_unknown_action_fail_closed(self):
        e = AssuranceEnvelope("env", "policy", surface(), 7, 10, 100, 20, 10, (("cpu", 80),), (("cpu", 100),), frozenset(("continue", "quarantine")))
        l = RuntimeAssuranceLedger(e)
        missing = RuntimeObservation("m", "w", surface(), 1, 20, "genesis", (), digest({"m": 1}))
        self.assertEqual(l.decide(missing, 21, "missing", AUTH)["action"], "quarantine")
        with self.assertRaises(RuntimeAssuranceError):
            AssuranceEnvelope("bad", "p", surface(), 7, 10, 100, 20, 10, (), (("cpu", 100),), frozenset(("invalid",)))

    def test_replay_surface_and_authority_denials(self):
        l = RuntimeAssuranceLedger(envelope())
        first = l.decide(obs(1), 21, "nonce", AUTH)
        with self.assertRaises(RuntimeAssuranceError): l.decide(obs(2, first["decision_digest"]), 22, "nonce", AUTH)
        with self.assertRaises(RuntimeAssuranceError): l.decide(obs(4, first["decision_digest"]), 22, "n4", AUTH)
        with self.assertRaises(RuntimeAssuranceError): l.decide(obs(2, first["decision_digest"], surf=surface("other")), 22, "n2", AUTH)
        with self.assertRaises(RuntimeAssuranceError): l.decide(obs(2, first["decision_digest"]), 22, "n2", dict(AUTH, model_output_is_authority=True))

    def test_expiry_and_chain_digest(self):
        l = RuntimeAssuranceLedger(envelope())
        first = l.decide(obs(1), 99, "n1", AUTH)
        self.assertEqual(first["action"], "quarantine")
        self.assertTrue(l.ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
