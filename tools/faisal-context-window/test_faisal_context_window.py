#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_context_window import COMPACTION_SCHEMA, ContextError, ContextItem, ContextLedger, ContextPolicy, digest, plan_context, verify_plan


def item(name: str, *, tokens: int, priority: int, recency: int, trust: int = 2, generation: int = 3, required: bool = False, pinned: bool = False, quarantined: bool = False, expires_at: int = 0) -> ContextItem:
    return ContextItem(name, "memory", digest({"source": name}), generation, trust, tokens, priority, recency, expires_at, pinned, required, quarantined)


def compaction(omitted: list[ContextItem], generation: int, tokens: int = 10) -> dict:
    return {
        "schema": COMPACTION_SCHEMA,
        "generation": generation,
        "source_item_digests": [i.item_digest for i in omitted],
        "summary_digest": digest({"summary": [i.item_id for i in omitted]}),
        "summary_tokens": tokens,
        "authority": {
            "model_output_is_authority": False,
            "compaction_is_authority": False,
            "context_is_execution_authority": False,
            "production_approval": False,
        },
    }


class ContextWindowTests(unittest.TestCase):
    def test_selection_filters_trust_quarantine_expiry_and_is_deterministic(self) -> None:
        items = [
            item("pinned", tokens=20, priority=1, recency=1, pinned=True),
            item("high", tokens=30, priority=10, recency=3),
            item("low", tokens=30, priority=1, recency=2),
            item("untrusted", tokens=1, priority=100, recency=10, trust=0),
            item("quarantine", tokens=1, priority=100, recency=10, quarantined=True),
            item("expired", tokens=1, priority=100, recency=10, expires_at=100),
        ]
        result = plan_context(items, ContextPolicy(50, minimum_trust_rank=1), generation=3, observed_at=100)
        self.assertEqual(result["selected_item_ids"], ["pinned", "high"])
        self.assertEqual(result["omitted_item_ids"], ["low"])
        self.assertEqual(result["rejections"]["untrusted"], "trust_below_minimum")
        self.assertFalse(result["complete_context"])
        self.assertFalse(result["authority"]["context_is_execution_authority"])

    def test_compaction_must_cover_exact_omitted_items(self) -> None:
        selected = item("selected", tokens=40, priority=10, recency=3)
        omitted = item("omitted", tokens=40, priority=1, recency=2)
        policy = ContextPolicy(50, allow_partial_context=False)
        with self.assertRaises(ContextError):
            plan_context([selected, omitted], policy, generation=3, observed_at=1)
        result = plan_context([selected, omitted], policy, generation=3, observed_at=1, compaction_receipt=compaction([omitted], 3, 5))
        self.assertEqual(result["total_token_estimate"], 45)
        self.assertEqual(result["compaction"]["source_item_digests"], [omitted.item_digest])
        self.assertFalse(result["complete_context"])

    def test_required_rejection_generation_and_expiry_fail_closed(self) -> None:
        with self.assertRaises(ContextError):
            plan_context([item("required", tokens=1, priority=1, recency=1, required=True, trust=0)], ContextPolicy(10), generation=3, observed_at=1)
        stale = plan_context([item("stale", tokens=1, priority=1, recency=1, generation=2)], ContextPolicy(10), generation=3, observed_at=1)
        self.assertEqual(stale["rejections"]["stale"], "generation_mismatch")
        expired = plan_context([item("expired", tokens=1, priority=1, recency=1, expires_at=2)], ContextPolicy(10), generation=3, observed_at=2)
        self.assertEqual(expired["rejections"]["expired"], "expired")

    def test_plan_verification_and_tamper_detection(self) -> None:
        result = plan_context([item("a", tokens=2, priority=1, recency=1)], ContextPolicy(10), generation=3, observed_at=1)
        verified = verify_plan(result, expected_generation=3)
        self.assertTrue(verified["verified"])
        tampered = copy.deepcopy(result)
        tampered["selected_item_ids"] = []
        with self.assertRaises(ContextError):
            verify_plan(tampered, expected_generation=3)
        with self.assertRaises(ContextError):
            verify_plan(result, expected_generation=4)

    def test_ledger_replay_and_authority_rejection(self) -> None:
        result = plan_context([item("a", tokens=2, priority=1, recency=1)], ContextPolicy(10), generation=3, observed_at=1)
        ledger = ContextLedger()
        admitted = ledger.admit(result, current_generation=3, nonce="n1")
        self.assertTrue(admitted["admitted"])
        with self.assertRaises(ContextError):
            ledger.admit(result, current_generation=3, nonce="n2")
        with self.assertRaises(ContextError):
            ledger.admit(result, current_generation=4, nonce="n3")
        bad = copy.deepcopy(result)
        bad["authority"]["model_output_is_authority"] = True
        with self.assertRaises(ContextError):
            ledger.admit(bad, current_generation=3, nonce="n4")

    def test_compaction_tamper_and_generation_fence(self) -> None:
        selected = item("selected", tokens=40, priority=10, recency=3)
        omitted = item("omitted", tokens=40, priority=1, recency=2)
        receipt = compaction([omitted], 3)
        receipt["source_item_digests"] = [digest({"other": "item"})]
        with self.assertRaises(ContextError):
            plan_context([selected, omitted], ContextPolicy(50, allow_partial_context=False), generation=3, observed_at=1, compaction_receipt=receipt)
        with self.assertRaises(ContextError):
            plan_context([selected, omitted], ContextPolicy(50, allow_partial_context=False), generation=3, observed_at=1, compaction_receipt=compaction([omitted], 4))


if __name__ == "__main__":
    unittest.main(verbosity=2)
