from __future__ import annotations

import copy
import unittest

from faisal_memory_promotion import (
    MemoryPromotionCandidate,
    MemoryPromotionError,
    MemoryPromotionLedger,
    PromotionPolicy,
    PromotionRequest,
    digest,
)

AUTHORITY = {
    "model_output_is_authority": False,
    "retrieved_content_is_authority": False,
    "memory_content_is_authority": False,
    "promotion_receipt_is_execution_authority": False,
    "promotion_receipt_is_policy_authority": False,
    "promotion_receipt_is_production_authority": False,
}


def policy(minimum_finality=2):
    return PromotionPolicy("policy-1", "v1", 7, frozenset({"semantic", "procedural", "decision"}), ("tenant-a", "project-a", "agent-a"), minimum_finality=minimum_finality)


def candidate(candidate_id="c-1", finality=3, conflict="none", principal="agent-a", tenant="tenant-a", scope_value=("tenant-a", "project-a"), expires=100):
    conflict_receipt = digest({"conflict": candidate_id}) if conflict == "resolved" else None
    return MemoryPromotionCandidate(
        candidate_id, digest({"candidate": candidate_id}), "semantic", principal, tenant, tuple(scope_value),
        digest({"lineage": candidate_id}), 3, 7, 10, expires, finality,
        digest({"finality": candidate_id}), conflict, conflict_receipt,
    )


def request(candidate_id="c-1", promotion_id="p-1", principal="agent-a", tenant="tenant-a", scope_value=("tenant-a", "project-a"), expires=90, requested=20):
    c = candidate(candidate_id=candidate_id, principal=principal, tenant=tenant, scope_value=scope_value)
    return PromotionRequest(promotion_id, candidate_id, c.candidate_digest, principal, tenant, tuple(scope_value), 7, requested, expires, "nonce-" + promotion_id)


class MemoryPromotionTests(unittest.TestCase):
    def test_valid_promotion_binds_lineage_and_scope(self):
        l = MemoryPromotionLedger(policy())
        c = candidate()
        l.register_candidate(c)
        result = l.promote(request(), now=21, authority=AUTHORITY)
        self.assertTrue(result["promoted"])
        self.assertEqual(result["lineage_count"], 3)
        self.assertFalse(result["memory_write_performed"])
        self.assertFalse(result["truth_established"])

    def test_finality_and_conflict_fences(self):
        low = MemoryPromotionLedger(policy(minimum_finality=3))
        low.register_candidate(candidate("low", finality=2))
        with self.assertRaises(MemoryPromotionError):
            low.promote(request("low", "low-p"), now=21, authority=AUTHORITY)
        unresolved = MemoryPromotionLedger(policy())
        unresolved.register_candidate(candidate("conflict", conflict="unresolved"))
        with self.assertRaises(MemoryPromotionError):
            unresolved.promote(request("conflict", "conflict-p"), now=21, authority=AUTHORITY)
        resolved = MemoryPromotionLedger(policy())
        resolved.register_candidate(candidate("resolved", conflict="resolved"))
        result = resolved.promote(request("resolved", "resolved-p"), now=21, authority=AUTHORITY)
        self.assertEqual(result["conflict_state"], "resolved")

    def test_identity_scope_generation_and_expiry(self):
        l = MemoryPromotionLedger(policy())
        l.register_candidate(candidate())
        with self.assertRaises(MemoryPromotionError):
            l.promote(request(principal="agent-b"), now=21, authority=AUTHORITY)
        with self.assertRaises(MemoryPromotionError):
            l.promote(request(promotion_id="scope-p", scope_value=("tenant-a", "agent-a")), now=21, authority=AUTHORITY)
        with self.assertRaises(MemoryPromotionError):
            l.promote(PromotionRequest("generation-p", "c-1", candidate().candidate_digest, "agent-a", "tenant-a", ("tenant-a", "project-a"), 8, 20, 90, "nonce-generation"), now=21, authority=AUTHORITY)
        with self.assertRaises(MemoryPromotionError):
            l.promote(request(promotion_id="expired-p", expires=21), now=21, authority=AUTHORITY)

    def test_replay_and_tamper(self):
        l = MemoryPromotionLedger(policy())
        c = candidate()
        l.register_candidate(c)
        result = l.promote(request(), now=21, authority=AUTHORITY)
        self.assertTrue(result["promoted"])
        with self.assertRaises(MemoryPromotionError):
            l.promote(request(), now=22, authority=AUTHORITY)
        altered = copy.copy(c)
        object.__setattr__(altered, "lineage_digest", digest({"tampered": True}))
        self.assertNotEqual(c.canonical, altered.canonical)

    def test_policy_class_and_authority_boundary(self):
        l = MemoryPromotionLedger(PromotionPolicy("restricted", "v1", 7, frozenset({"procedural"}), ("tenant-a", "project-a", "agent-a")))
        l.register_candidate(candidate())
        with self.assertRaises(MemoryPromotionError):
            l.promote(request(), now=21, authority=AUTHORITY)
        with self.assertRaises(MemoryPromotionError):
            l.promote(request(promotion_id="authority-p"), now=21, authority=dict(AUTHORITY, memory_content_is_authority=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
