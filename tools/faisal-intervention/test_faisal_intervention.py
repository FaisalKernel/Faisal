from __future__ import annotations

import copy
import unittest

from faisal_intervention import (
    InterventionError,
    InterventionLedger,
    InterventionPolicy,
    InterventionRequest,
    digest,
)

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_description_is_authority": False,
    "tool_result_is_authority": False,
    "observation_is_authority": False,
    "intervention_receipt_is_execution_authority": False,
    "intervention_receipt_is_production_authority": False,
}


def request(intervention_id="i-1", intervention="pause", generation=7, observed=10, expires=100, attempt=1, approval=None):
    return InterventionRequest(
        intervention_id, "supervisor-a", "task-1", intervention, generation,
        observed, expires, digest({"observation": intervention_id}),
        digest({"state": intervention_id}), digest({"checkpoint": intervention_id}),
        digest({"proposed": intervention_id}), digest({"reason": intervention_id}),
        attempt, approval,
    )


def ledger(approval=frozenset(), cooldown=0, max_attempts=1):
    return InterventionLedger(InterventionPolicy(
        "policy-1", "v1", 7,
        frozenset({"pause", "checkpoint", "downgrade", "retry", "quarantine", "rollback", "terminate"}),
        cooldown=cooldown, approval_required=approval, max_attempts=max_attempts,
    ))


class InterventionTests(unittest.TestCase):
    def test_valid_admission_and_completion(self):
        l = ledger()
        result = l.admit(request(), now=20, authority=AUTHORITY)
        self.assertEqual(result["verdict"], "admit_bounded_intervention")
        self.assertFalse(result["execution_performed"])
        completed = l.complete("i-1", post_state_digest=digest({"post": 1}), post_trace_digest=digest({"trace": 1}), now=21, authority=AUTHORITY)
        self.assertTrue(completed["completed"])
        self.assertFalse(completed["execution_performed"])

    def test_high_impact_approval(self):
        l = ledger(frozenset({"terminate", "rollback"}))
        pending = l.admit(request("pending", "terminate"), now=20, authority=AUTHORITY)
        self.assertEqual(pending["verdict"], "require_blocking_approval")
        approved = ledger(frozenset({"terminate"})).admit(
            request("approved", "terminate", approval=digest({"approval": True})), now=20, authority=AUTHORITY)
        self.assertEqual(approved["verdict"], "admit_bounded_intervention")

    def test_cooldown_and_attempt_fences(self):
        l = ledger(cooldown=10, max_attempts=2)
        l.admit(request("first"), now=20, authority=AUTHORITY)
        with self.assertRaises(InterventionError):
            l.admit(request("second"), now=25, authority=AUTHORITY)
        with self.assertRaises(InterventionError):
            l.admit(request("third", attempt=3), now=40, authority=AUTHORITY)

    def test_generation_expiry_and_policy_fences(self):
        with self.assertRaises(InterventionError):
            ledger().admit(request("stale", generation=8), now=20, authority=AUTHORITY)
        with self.assertRaises(InterventionError):
            ledger().admit(request("expired", expires=20), now=20, authority=AUTHORITY)
        restricted = InterventionLedger(InterventionPolicy("p", "v1", 7, frozenset({"pause"})))
        with self.assertRaises(InterventionError):
            restricted.admit(request("denied", "terminate"), now=20, authority=AUTHORITY)

    def test_replay_completion_and_tamper(self):
        l = ledger()
        req = request()
        original = req.request_digest
        altered = copy.copy(req)
        object.__setattr__(altered, "proposed_state_digest", digest({"tampered": True}))
        self.assertNotEqual(original, altered.request_digest)
        l.admit(req, now=20, authority=AUTHORITY)
        with self.assertRaises(InterventionError):
            l.admit(req, now=21, authority=AUTHORITY)
        l.complete("i-1", post_state_digest=digest({"post": 1}), post_trace_digest=digest({"trace": 1}), now=22, authority=AUTHORITY)
        with self.assertRaises(InterventionError):
            l.complete("i-1", post_state_digest=digest({"post": 2}), post_trace_digest=digest({"trace": 2}), now=23, authority=AUTHORITY)

    def test_checkpoint_and_authority_boundaries(self):
        # Construction always binds a checkpoint digest; this test verifies the
        # high-impact request and authority boundary rather than performing it.
        bad_authority = dict(AUTHORITY, observation_is_authority=True)
        with self.assertRaises(InterventionError):
            ledger().admit(request("bad-authority", "checkpoint"), now=20, authority=bad_authority)
        with self.assertRaises(InterventionError):
            ledger().complete("unknown", post_state_digest=digest({"s": 1}), post_trace_digest=digest({"t": 1}), now=20, authority=AUTHORITY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
