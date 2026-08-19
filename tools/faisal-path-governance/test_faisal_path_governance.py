from __future__ import annotations

import copy
import unittest

from faisal_path_governance import (
    ActionRequest,
    PathGovernanceError,
    PathGovernanceLedger,
    PathPolicy,
    PathRule,
    PathStep,
    digest,
)

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_description_is_authority": False,
    "tool_result_is_authority": False,
    "observation_is_authority": False,
    "path_receipt_is_execution_authority": False,
    "path_receipt_is_production_authority": False,
}


def step(step_id: str = "s-1", actor: str = "agent-a", labels=frozenset({"public_read"}), at: int = 1) -> PathStep:
    return PathStep(step_id, actor, "tool_call", frozenset(labels), 7, at, digest({"in": step_id}), digest({"out": step_id}))


def request(decision: str = "d-1", actor: str = "agent-a", labels=frozenset({"public_write"}), cost: int = 2, approval=None, terminal=False) -> ActionRequest:
    return ActionRequest(
        decision, actor, "tool_call", frozenset(labels), 7,
        digest({"request": decision}), digest({"proposal": decision}), cost,
        approval_digest=approval,
        terminal_result_digest=digest({"result": decision}) if terminal else None,
        terminal_trace_digest=digest({"trace": decision}) if terminal else None,
    )


def ledger(rules=(), budget=100) -> PathGovernanceLedger:
    return PathGovernanceLedger(PathPolicy("p-1", "v1", 7, max_steps=16, max_risk_budget=budget, rules=tuple(rules)))


class PathGovernanceTests(unittest.TestCase):
    def test_valid_admission_and_terminal_linkage(self) -> None:
        l = ledger()
        l.append_observed(step())
        result = l.admit(request(terminal=True), now=2, authority=AUTHORITY)
        self.assertEqual(result["verdict"], "allow_with_policy")
        self.assertTrue(result["terminal_result_linked"])
        self.assertEqual(result["path_length"], 1)

    def test_path_sensitive_deny(self) -> None:
        rule = PathRule("no-private-export", "v1", frozenset({"private_read"}), frozenset({"external_write"}), deny_on_match=True)
        l = ledger((rule,))
        l.append_observed(step(labels=frozenset({"private_read"})))
        result = l.admit(request(labels=frozenset({"external_write"})), now=2, authority=AUTHORITY)
        self.assertEqual(result["verdict"], "deny")
        self.assertEqual(result["reason"], "path_rule:no-private-export")

    def test_approval_gate(self) -> None:
        rule = PathRule("approval-required", "v1", frozenset({"sensitive_read"}), frozenset({"external_write"}), deny_on_match=False, require_approval=True)
        l = ledger((rule,))
        l.append_observed(step(labels=frozenset({"sensitive_read"})))
        pending = l.admit(request("pending", labels=frozenset({"external_write"})), now=2, authority=AUTHORITY)
        self.assertEqual(pending["verdict"], "require_blocking_approval")
        approved = ledger((rule,))
        approved.append_observed(step(labels=frozenset({"sensitive_read"})))
        result = approved.admit(request("approved", labels=frozenset({"external_write"}), approval=digest({"approval": True})), now=2, authority=AUTHORITY)
        self.assertEqual(result["verdict"], "allow_with_policy")

    def test_budget_denial(self) -> None:
        l = ledger(budget=3)
        l.append_observed(step(labels=frozenset({"risk:one", "risk:two"})))
        result = l.admit(request(cost=2), now=2, authority=AUTHORITY)
        self.assertEqual(result["verdict"], "deny")
        self.assertEqual(result["reason"], "risk_budget_exceeded")

    def test_actor_transition_requires_handoff_label(self) -> None:
        l = ledger()
        l.append_observed(step(actor="agent-a"))
        with self.assertRaises(PathGovernanceError):
            l.admit(request("bad-actor", actor="agent-b"), now=2, authority=AUTHORITY)
        result = l.admit(request("linked-actor", actor="agent-b", labels=frozenset({"delegated_handoff"})), now=2, authority=AUTHORITY)
        self.assertEqual(result["verdict"], "allow_with_policy")

    def test_generation_time_replay_and_tamper(self) -> None:
        l = ledger()
        with self.assertRaises(PathGovernanceError):
            l.append_observed(PathStep("stale", "agent-a", "tool_call", frozenset(), 8, 1, digest({"a": 1}), digest({"b": 1})))
        l.append_observed(step())
        l.admit(request(), now=2, authority=AUTHORITY)
        with self.assertRaises(PathGovernanceError):
            l.admit(request(), now=3, authority=AUTHORITY)
        altered = copy.copy(request("tamper"))
        object.__setattr__(altered, "risk_cost", 999)
        self.assertNotEqual(request("tamper").request_digest, altered.request_digest)

    def test_authority_and_terminal_fences(self) -> None:
        bad = dict(AUTHORITY, model_output_is_authority=True)
        with self.assertRaises(PathGovernanceError):
            ledger().admit(request(), now=1, authority=bad)
        with self.assertRaises(PathGovernanceError):
            ActionRequest("incomplete", "agent-a", "tool_call", frozenset(), 7, digest({"i": 1}), digest({"o": 1}), 1, terminal_result_digest=digest({"r": 1}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
