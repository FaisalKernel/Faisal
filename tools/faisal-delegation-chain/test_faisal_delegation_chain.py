from __future__ import annotations

import unittest

from faisal_delegation_chain import (
    ChainPolicy,
    DelegationChainError,
    DelegationChainLedger,
    DelegationHop,
    UseRequest,
    digest,
)

AUTHORITY = {
    "model_output_is_authority": False,
    "agent_claim_is_authority": False,
    "credential_metadata_is_authority": False,
    "delegation_receipt_is_execution_authority": False,
    "delegation_receipt_is_policy_authority": False,
    "delegation_receipt_is_production_authority": False,
}

ROUTE = digest({"route": "task-1"})


def policy():
    return ChainPolicy("chain-policy", "v1", 7, "audience-tools", frozenset({"read:catalog", "write:draft", "publish:report"}), max_depth=4, max_ttl=120, max_execution_count=4)


def hop(hop_id, issuer, subject, parent=None, scope_value=("read:catalog", "write:draft"), expires=90, limit=4):
    return DelegationHop("chain-1", hop_id, issuer, subject, parent, frozenset(scope_value), "audience-tools", "task-1", ROUTE, 7, 10, expires, limit)


def req(use_id="use-1", leaf="hop-2", requested=("read:catalog",), count=1, expires=80):
    return UseRequest(use_id, "chain-1", leaf, "audience-tools", "task-1", ROUTE, frozenset(requested), 7, count, 20, expires, "nonce-" + use_id)


def chain():
    l = DelegationChainLedger(policy())
    root = hop("hop-1", "principal", "agent-a")
    root_digest = l.register_hop(root)
    child = hop("hop-2", "agent-a", "agent-b", root_digest, ("read:catalog",))
    l.register_hop(child)
    return l, root, child


class DelegationChainTests(unittest.TestCase):
    def test_valid_attenuated_chain(self):
        l, _, _ = chain()
        result = l.admit_use(req(), now=21, authority=AUTHORITY)
        self.assertTrue(result["admitted"])
        self.assertEqual(result["chain_depth"], 2)
        self.assertEqual(result["effective_capabilities"], ["read:catalog"])
        self.assertFalse(result["credentials_issued"])

    def test_attenuation_and_subject_linkage(self):
        l = DelegationChainLedger(policy())
        root_digest = l.register_hop(hop("root", "principal", "agent-a"))
        with self.assertRaises(DelegationChainError):
            l.register_hop(hop("amplify", "agent-a", "agent-b", root_digest, ("read:catalog", "publish:report")))
        with self.assertRaises(DelegationChainError):
            l.register_hop(hop("wrong-issuer", "other", "agent-b", root_digest, ("read:catalog",)))

    def test_binding_and_execution_count(self):
        l, _, _ = chain()
        with self.assertRaises(DelegationChainError):
            l.admit_use(UseRequest("aud", "chain-1", "hop-2", "wrong-aud", "task-1", ROUTE, frozenset({"read:catalog"}), 7, 1, 20, 80, "nonce-aud"), now=21, authority=AUTHORITY)
        with self.assertRaises(DelegationChainError):
            l.admit_use(UseRequest("route", "chain-1", "hop-2", "audience-tools", "task-1", digest({"other": 1}), frozenset({"read:catalog"}), 7, 1, 20, 80, "nonce-route"), now=21, authority=AUTHORITY)
        with self.assertRaises(DelegationChainError):
            l.admit_use(req("count", count=5), now=21, authority=AUTHORITY)

    def test_revocation_and_expiry_generation(self):
        l, _, child = chain()
        l.revoke(child.hop_id, epoch=1)
        with self.assertRaises(DelegationChainError):
            l.admit_use(req("revoked"), now=21, authority=AUTHORITY)
        expired = DelegationChainLedger(policy())
        root_digest = expired.register_hop(hop("expired-root", "principal", "agent-a", expires=21))
        expired.register_hop(hop("expired-child", "agent-a", "agent-b", root_digest, expires=21))
        with self.assertRaises(DelegationChainError):
            expired.admit_use(req("expired", leaf="expired-child", expires=80), now=21, authority=AUTHORITY)

    def test_replay_and_authority_boundary(self):
        l, _, _ = chain()
        l.admit_use(req(), now=21, authority=AUTHORITY)
        with self.assertRaises(DelegationChainError):
            l.admit_use(req(), now=22, authority=AUTHORITY)
        with self.assertRaises(DelegationChainError):
            l.admit_use(req("authority"), now=21, authority=dict(AUTHORITY, agent_claim_is_authority=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
