#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_session_risk import PolicyDecisionRequest, RiskEvent, RiskPolicy, SessionRiskError, SessionRiskLedger, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_description_is_authority": False,
    "tool_result_is_authority": False,
    "policy_receipt_is_production_authority": False,
}


def event(event_id: str, capabilities=(), taints=(), at: int = 100, generation: int = 4) -> RiskEvent:
    return RiskEvent(event_id, "observed", frozenset(capabilities), frozenset(taints), generation, at, digest({"source": event_id}), digest({"context": event_id}))


def request(decision_id: str, capabilities=(), taints=(), generation: int = 4, approval: str | None = None, model_output: str | None = None) -> PolicyDecisionRequest:
    return PolicyDecisionRequest(decision_id, "session-1", generation, frozenset(capabilities), frozenset(taints), digest({"context": decision_id}), digest({"auth": decision_id}), approval, model_output)


class SessionRiskTests(unittest.TestCase):
    def test_bounded_policy_match_allows_safe_request(self) -> None:
        ledger = SessionRiskLedger(RiskPolicy("policy", "1", 4))
        result = ledger.decide(request("safe", capabilities=("local_read",)), now=120, nonce="n1", authority=AUTHORITY)
        self.assertEqual(result["verdict"], "allow_with_policy")
        self.assertFalse(result["authority"]["policy_receipt_is_production_authority"])

    def test_lethal_trifecta_requires_blocking_approval(self) -> None:
        ledger = SessionRiskLedger(RiskPolicy("policy", "1", 4))
        ledger.append(event("private", capabilities=("private_data_access",)))
        ledger.append(event("untrusted", capabilities=("untrusted_content_exposure",), at=101))
        blocked = ledger.decide(request("external", capabilities=("external_communication",)), now=120, nonce="n2", authority=AUTHORITY)
        self.assertEqual(blocked["verdict"], "require_blocking_approval")
        self.assertEqual(blocked["reason"], "lethal_trifecta")
        approved = ledger.decide(request("external-approved", capabilities=("external_communication",), approval=digest({"operator": "approved"})), now=120, nonce="n3", authority=AUTHORITY)
        self.assertEqual(approved["verdict"], "allow_with_policy")
        self.assertTrue(approved["lethal_trifecta"])

    def test_critical_taint_denies_even_with_approval(self) -> None:
        ledger = SessionRiskLedger(RiskPolicy("policy", "1", 4))
        result = ledger.decide(request("critical", taints=("critical_taint",), approval=digest({"operator": "approved"})), now=120, nonce="n4", authority=AUTHORITY)
        self.assertEqual(result["verdict"], "deny")
        self.assertEqual(result["reason"], "critical_taint")

    def test_unknown_behavior_requires_blocking_approval(self) -> None:
        ledger = SessionRiskLedger(RiskPolicy("policy", "1", 4))
        result = ledger.decide(request("unknown", taints=("unknown_tool_behavior",)), now=120, nonce="n5", authority=AUTHORITY)
        self.assertEqual(result["verdict"], "require_blocking_approval")
        self.assertEqual(result["reason"], "unknown_tool_behavior")

    def test_generation_monotonic_event_and_replay_fences(self) -> None:
        ledger = SessionRiskLedger(RiskPolicy("policy", "1", 4))
        with self.assertRaises(SessionRiskError):
            ledger.append(event("stale", generation=5))
        ledger.append(event("first"))
        with self.assertRaises(SessionRiskError):
            ledger.append(event("backwards", at=99))
        result = ledger.decide(request("one"), now=120, nonce="n6", authority=AUTHORITY)
        self.assertEqual(result["generation"], 4)
        with self.assertRaises(SessionRiskError):
            ledger.decide(request("one"), now=120, nonce="n7", authority=AUTHORITY)
        with self.assertRaises(SessionRiskError):
            ledger.decide(request("stale-decision", generation=5), now=120, nonce="n8", authority=AUTHORITY)

    def test_authority_tamper_and_model_output_are_non_authority(self) -> None:
        ledger = SessionRiskLedger(RiskPolicy("policy", "1", 4))
        model_digest = digest({"model": "suggested_allow"})
        result = ledger.decide(request("model", model_output=model_digest), now=120, nonce="n9", authority=AUTHORITY)
        self.assertEqual(result["verdict"], "allow_with_policy")
        tampered = copy.deepcopy(result)
        tampered["authority"]["model_output_is_authority"] = True
        self.assertNotEqual(tampered["decision_digest"], digest({k: v for k, v in tampered.items() if k != "decision_digest"}))
        bad_authority = dict(AUTHORITY, policy_receipt_is_production_authority=True)
        with self.assertRaises(SessionRiskError):
            ledger.decide(request("bad-authority"), now=120, nonce="n10", authority=bad_authority)


if __name__ == "__main__":
    unittest.main(verbosity=2)
