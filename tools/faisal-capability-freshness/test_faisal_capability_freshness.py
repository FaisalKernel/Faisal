from __future__ import annotations

import unittest

from faisal_capability_freshness import CapabilityFreshnessError, CapabilityFreshnessLedger, CapabilityManifest, FreshnessPolicy, FreshnessRequest, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_metadata_is_authority": False,
    "manifest_claim_is_attestation": False,
    "freshness_receipt_is_execution_authority": False,
    "freshness_receipt_is_policy_authority": False,
    "freshness_receipt_is_production_authority": False,
}


def policy():
    return FreshnessPolicy("freshness-policy", "v1", 7, ("model-a",), ("read", "write"), ("route-a",), "audience-tools", max_ttl=120)


def manifest(manifest_id="m-1", tools=("read",), model="model-a", route="route-a", generation=7, key_epoch=1, expires=100, revoked=False):
    return CapabilityManifest(manifest_id, "agent-a", model, "v1", tuple(tools), route, "audience-tools", "task-1", generation, key_epoch, 10, expires, revoked)


def request(admitted, observed, request_id="use-1", expires=80, generation=7, key_epoch=1):
    return FreshnessRequest(request_id, "agent-a", "task-1", "audience-tools", "route-a", admitted.manifest_id, admitted.manifest_digest, observed.manifest_id, observed.manifest_digest, digest({"hop": 1}), generation, generation, key_epoch, key_epoch, 20, expires, "nonce-" + request_id)


def ledger_pair():
    l = CapabilityFreshnessLedger(policy())
    a = manifest(); o = manifest("m-2")
    l.register_manifest(a); l.register_manifest(o)
    return l, a, o


class CapabilityFreshnessTests(unittest.TestCase):
    def test_valid_unchanged_manifest(self):
        l, a, o = ledger_pair()
        result = l.admit(request(a, o), now=21, authority=AUTHORITY)
        self.assertTrue(result["fresh"])
        self.assertFalse(result["capability_drift"])
        self.assertFalse(result["cryptographic_attestation_verified"])
        self.assertFalse(result["tools_executed"])

    def test_tool_model_and_route_drift(self):
        for name, changed in (("tools", {"tools": ("read", "write")}), ("model", {"model": "model-b"}), ("route", {"route": "route-b"})):
            l = CapabilityFreshnessLedger(FreshnessPolicy("p-" + name, "v1", 7, ("model-a", "model-b"), ("read", "write"), ("route-a", "route-b"), "audience-tools"))
            a = manifest("a-" + name); o = manifest("o-" + name, **changed)
            l.register_manifest(a); l.register_manifest(o)
            with self.assertRaises(CapabilityFreshnessError):
                l.admit(request(a, o, name), now=21, authority=AUTHORITY)

    def test_generation_epoch_revocation_and_expiry(self):
        l, a, o = ledger_pair()
        with self.assertRaises(CapabilityFreshnessError):
            l.admit(request(a, o, "generation", generation=8), now=21, authority=AUTHORITY)
        l.revoke("agent-a", key_epoch=2)
        with self.assertRaises(CapabilityFreshnessError):
            l.admit(request(a, o, "revoked"), now=21, authority=AUTHORITY)
        expired = CapabilityFreshnessLedger(policy()); ea = manifest("ea", expires=21); eo = manifest("eo", expires=21)
        expired.register_manifest(ea); expired.register_manifest(eo)
        with self.assertRaises(CapabilityFreshnessError):
            expired.admit(request(ea, eo, "expired", expires=80), now=21, authority=AUTHORITY)

    def test_replay_tamper_and_authority_boundary(self):
        l, a, o = ledger_pair()
        l.admit(request(a, o), now=21, authority=AUTHORITY)
        with self.assertRaises(CapabilityFreshnessError):
            l.admit(request(a, o), now=22, authority=AUTHORITY)
        altered = manifest("tampered", tools=("write",))
        l.register_manifest(altered)
        with self.assertRaises(CapabilityFreshnessError):
            l.admit(request(a, altered, "tamper"), now=21, authority=AUTHORITY)
        with self.assertRaises(CapabilityFreshnessError):
            l.admit(request(a, o, "authority"), now=21, authority=dict(AUTHORITY, manifest_claim_is_attestation=True))

    def test_policy_and_ttl_fences(self):
        l = CapabilityFreshnessLedger(policy())
        denied_model = manifest("denied", model="model-b")
        with self.assertRaises(CapabilityFreshnessError):
            l.register_manifest(denied_model)
        a = manifest("a-ttl"); o = manifest("o-ttl")
        l.register_manifest(a); l.register_manifest(o)
        with self.assertRaises(CapabilityFreshnessError):
            l.admit(request(a, o, "ttl", expires=200), now=21, authority=AUTHORITY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
