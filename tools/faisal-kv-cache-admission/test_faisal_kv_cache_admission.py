import unittest
from faisal_kv_cache_admission import AgentHints, CacheAdmissionRequest, CachePolicy, KVCacheAdmissionError, KVCacheAdmissionLedger, digest

AUTH = {"model_output_is_authority": False, "provider_metadata_is_authority": False, "cache_hint_is_execution_authority": False, "cache_hint_is_policy_authority": False, "production_approval": False}
SURFACE = digest({"surface": "s1"})
ROUTE = digest({"route": "r1"})
POLICY = CachePolicy("cache-policy", 7, 100, 50, 4096, 2)

def hints(priority=10, output=512, speculative=True, ttl=60, pin=True):
    return AgentHints(priority, output, speculative, ttl, pin)

def request(i, prior="genesis", generation=7, issued=20, h=None, surface=SURFACE, route=ROUTE):
    return CacheAdmissionRequest(f"req-{i}", "session-1", route, surface, generation, issued, h or hints(), prior)

class KVCacheAdmissionTests(unittest.TestCase):
    def test_valid_admission_and_recommendation(self):
        ledger = KVCacheAdmissionLedger(POLICY)
        result = ledger.admit(request(1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        self.assertEqual(result["status"], "admitted")
        self.assertEqual(result["recommendation"]["priority"], 10)
        self.assertTrue(result["recommendation"]["speculative_prefill"])
        self.assertTrue(result["recommendation"]["pin"])
        self.assertFalse(result["recommendation"]["memory_pinned"])

    def test_session_chain_replay_and_authority_denials(self):
        ledger = KVCacheAdmissionLedger(POLICY)
        first = ledger.admit(request(1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        with self.assertRaises(KVCacheAdmissionError): ledger.admit(request(2), current_generation=7, nonce="n2", authority=AUTH, now=22)
        with self.assertRaises(KVCacheAdmissionError): ledger.admit(request(2, prior=first["record_digest"]), current_generation=7, nonce="n1", authority=AUTH, now=22)
        with self.assertRaises(KVCacheAdmissionError): ledger.admit(request(2, prior=first["record_digest"]), current_generation=7, nonce="n2", authority=dict(AUTH, model_output_is_authority=True), now=22)
        with self.assertRaises(KVCacheAdmissionError): ledger.admit(request(2, prior=first["record_digest"], surface=digest({"surface": "other"})), current_generation=7, nonce="n3", authority=AUTH, now=22)

    def test_policy_and_freshness_gates(self):
        cases = [
            ("generation", request(1, generation=8), {"current_generation": 7, "nonce": "g"}, 21),
            ("ttl", request(1, h=hints(ttl=101)), {"current_generation": 7, "nonce": "t"}, 21),
            ("priority", request(1, h=hints(priority=51)), {"current_generation": 7, "nonce": "p"}, 21),
            ("output", request(1, h=hints(output=4097)), {"current_generation": 7, "nonce": "o"}, 21),
            ("stale", request(1, issued=0), {"current_generation": 7, "nonce": "s"}, 101),
        ]
        for name, req, kwargs, now in cases:
            with self.subTest(name=name), self.assertRaises(KVCacheAdmissionError):
                KVCacheAdmissionLedger(POLICY).admit(req, authority=AUTH, now=now, **kwargs)

    def test_pinned_capacity_and_digest(self):
        ledger = KVCacheAdmissionLedger(POLICY)
        first = ledger.admit(request(1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        second = CacheAdmissionRequest("req-2", "session-2", ROUTE, SURFACE, 7, 21, hints(pin=True), "genesis")
        ledger.admit(second, current_generation=7, nonce="n2", authority=AUTH, now=22)
        third = CacheAdmissionRequest("req-3", "session-3", ROUTE, SURFACE, 7, 22, hints(pin=True), "genesis")
        with self.assertRaises(KVCacheAdmissionError): ledger.admit(third, current_generation=7, nonce="n3", authority=AUTH, now=23)
        self.assertTrue(ledger.ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
