from __future__ import annotations

import unittest

from faisal_evidence_freshness import EvidenceFreshnessError, EvidenceFreshnessLedger, FreshnessPolicy, QualificationLease, QualificationSurface, digest

AUTHORITY = {
    "evidence_is_truth": False,
    "evidence_is_execution_authority": False,
    "evidence_is_policy_authority": False,
    "evidence_is_production_authority": False,
    "qualification_receipt_is_attestation": False,
}


def policy():
    return FreshnessPolicy("freshness-policy", "v1", 7, 47, max_evidence_age=100, max_lease_ttl=120)


def surface(generation=7, abi=47, suffix="s1"):
    return QualificationSurface(suffix, digest({"model": suffix}), digest({"tool": suffix}), digest({"route": suffix}), digest({"policy": suffix}), digest({"hardware": suffix}), digest({"env": suffix}), digest({"bench": suffix}), abi, generation)


def lease(s, policy_obj=None, lease_id="lease-1", evidence_recorded=20, issued=30, expires=100, drift=(), critical=False, quarantined=False, revoked=False):
    p = policy_obj or policy()
    return QualificationLease(lease_id, "qual-1", s.surface_digest, digest({"evidence": s.surface_digest}), digest({"provenance": s.surface_digest}), p.policy_digest, p.generation, issued, evidence_recorded, expires, tuple(drift), critical, quarantined, revoked)


class EvidenceFreshnessTests(unittest.TestCase):
    def test_valid_fresh_lease_and_revoke(self):
        ledger = EvidenceFreshnessLedger(policy()); s = surface(); l = lease(s)
        result = ledger.admit(s, l, now=31, authority=AUTHORITY, nonce="n1")
        self.assertTrue(result["freshness_verified"])
        self.assertFalse(result["production_approved"])
        self.assertTrue(ledger.revoke("lease-1")["revoked"])

    def test_surface_and_drift_gates(self):
        cases = {
            "surface": lambda: EvidenceFreshnessLedger(policy()).admit(surface(), lease(surface("7", 47, "other")), now=31, authority=AUTHORITY, nonce="surface"),
            "critical_drift": lambda: EvidenceFreshnessLedger(policy()).admit(surface(), lease(surface(), drift=("model",), critical=True), now=31, authority=AUTHORITY, nonce="drift"),
            "noncritical_but_policy_critical": lambda: EvidenceFreshnessLedger(policy()).admit(surface(), lease(surface(), drift=("route",)), now=31, authority=AUTHORITY, nonce="route"),
        }
        for name, fn in cases.items():
            with self.subTest(name=name), self.assertRaises(EvidenceFreshnessError):
                fn()

    def test_stale_generation_abi_and_expiry_gates(self):
        cases = {
            "stale": lambda: EvidenceFreshnessLedger(policy()).admit(surface(), lease(surface(), evidence_recorded=-1), now=31, authority=AUTHORITY, nonce="stale"),
            "generation": lambda: EvidenceFreshnessLedger(policy()).admit(surface(generation=8), lease(surface(generation=8), policy_obj=policy()), now=31, authority=AUTHORITY, nonce="generation"),
            "abi": lambda: EvidenceFreshnessLedger(policy()).admit(surface(abi=48), lease(surface(abi=48), policy_obj=policy()), now=31, authority=AUTHORITY, nonce="abi"),
            "expiry": lambda: EvidenceFreshnessLedger(policy()).admit(surface(), lease(surface(), expires=31), now=31, authority=AUTHORITY, nonce="expiry"),
            "ttl": lambda: EvidenceFreshnessLedger(policy()).admit(surface(), lease(surface(), expires=200), now=31, authority=AUTHORITY, nonce="ttl"),
        }
        for name, fn in cases.items():
            with self.subTest(name=name), self.assertRaises(EvidenceFreshnessError):
                fn()

    def test_quarantine_replay_nonce_tamper_authority(self):
        ledger = EvidenceFreshnessLedger(policy()); s = surface()
        l = lease(s); ledger.admit(s, l, now=31, authority=AUTHORITY, nonce="n1")
        self.assertTrue(ledger.quarantine("lease-1")["quarantined"])
        with self.assertRaises(EvidenceFreshnessError):
            ledger.admit(s, l, now=31, authority=AUTHORITY, nonce="n2")
        with self.assertRaises(EvidenceFreshnessError):
            ledger.admit(s, lease(s, lease_id="lease-2"), now=31, authority=AUTHORITY, nonce="n1")
        with self.assertRaises(EvidenceFreshnessError):
            ledger.admit(s, lease(s, lease_id="lease-3"), now=31, authority=dict(AUTHORITY, evidence_is_truth=True), nonce="n3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
