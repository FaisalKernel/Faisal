from __future__ import annotations

import copy
import unittest

from faisal_task_routing import (
    TaskRouteLeaseRequest,
    TaskRoutingError,
    TaskRoutingLedger,
    TaskRoutingPolicy,
    TaskTurnRequest,
    digest,
)

AUTHORITY = {
    "model_output_is_authority": False,
    "endpoint_metadata_is_authority": False,
    "route_outcome_is_authority": False,
    "task_routing_receipt_is_execution_authority": False,
    "task_routing_receipt_is_production_authority": False,
}


def lease(lease_id="l-1", task_id="task-1", selected="model-a", generation=7, admitted=10, expires=100, max_turns=8):
    return TaskRouteLeaseRequest(
        lease_id, task_id, digest({"route": lease_id}), ("model-a", "model-b"), selected,
        generation, admitted, expires, digest({"context": task_id}), digest({"route-evidence": lease_id}), max_turns,
    )


def turn(sequence, endpoint="model-a", lease_id="l-1", task_id="task-1", generation=7):
    return TaskTurnRequest(
        f"turn-{sequence}", lease_id, task_id, digest({"request": sequence}), endpoint,
        generation, sequence, 20 + sequence,
    )


def ledger():
    return TaskRoutingLedger(TaskRoutingPolicy("policy-1", "v1", 7, max_tasks=8, max_turns=8, max_ttl=120))


class TaskRoutingTests(unittest.TestCase):
    def test_admit_pins_backend_and_completes_delayed_feedback(self):
        l = ledger()
        admitted = l.admit(lease(), now=20, authority=AUTHORITY)
        self.assertTrue(admitted["pinned_for_task"])
        l.admit_turn(turn(1), now=21, authority=AUTHORITY)
        l.admit_turn(turn(2), now=22, authority=AUTHORITY)
        completed = l.complete(lease_id="l-1", success=True, quality_milli=950, latency_ms=120, evidence_digest=digest({"quality": 1}), terminal_trace_digest=digest({"trace": 1}), now=23, authority=AUTHORITY)
        self.assertTrue(completed["terminal"])
        self.assertTrue(completed["delayed_feedback"])
        self.assertFalse(completed["routing_statistics_updated"])
        self.assertEqual(completed["turn_count"], 2)

    def test_backend_pin_and_sequence_fences(self):
        l = ledger()
        l.admit(lease(), now=20, authority=AUTHORITY)
        with self.assertRaises(TaskRoutingError):
            l.admit_turn(turn(1, endpoint="model-b"), now=21, authority=AUTHORITY)
        with self.assertRaises(TaskRoutingError):
            l.admit_turn(turn(2), now=22, authority=AUTHORITY)
        l.admit_turn(turn(1), now=21, authority=AUTHORITY)
        with self.assertRaises(TaskRoutingError):
            l.admit_turn(turn(1), now=22, authority=AUTHORITY)

    def test_generation_identity_and_expiry(self):
        with self.assertRaises(TaskRoutingError):
            ledger().admit(lease("stale", generation=8), now=20, authority=AUTHORITY)
        with self.assertRaises(TaskRoutingError):
            ledger().admit(lease("expired", expires=20), now=20, authority=AUTHORITY)
        l = ledger()
        l.admit(lease("late", expires=100), now=20, authority=AUTHORITY)
        with self.assertRaises(TaskRoutingError):
            l.admit_turn(turn(1, lease_id="late"), now=100, authority=AUTHORITY)

    def test_terminal_replay_and_empty_completion(self):
        l = ledger()
        l.admit(lease(), now=20, authority=AUTHORITY)
        with self.assertRaises(TaskRoutingError):
            l.complete(lease_id="l-1", success=False, quality_milli=0, latency_ms=1, evidence_digest=digest({"e": 1}), terminal_trace_digest=digest({"t": 1}), now=21, authority=AUTHORITY)
        l.admit_turn(turn(1), now=21, authority=AUTHORITY)
        l.complete(lease_id="l-1", success=True, quality_milli=700, latency_ms=2, evidence_digest=digest({"e": 2}), terminal_trace_digest=digest({"t": 2}), now=22, authority=AUTHORITY)
        with self.assertRaises(TaskRoutingError):
            l.complete(lease_id="l-1", success=True, quality_milli=700, latency_ms=2, evidence_digest=digest({"e": 3}), terminal_trace_digest=digest({"t": 3}), now=23, authority=AUTHORITY)

    def test_lease_and_turn_tamper(self):
        original = lease()
        altered = copy.copy(original)
        object.__setattr__(altered, "selected_endpoint_id", "model-b")
        self.assertNotEqual(original.lease_digest, altered.lease_digest)
        turn_original = turn(1)
        turn_altered = copy.copy(turn_original)
        object.__setattr__(turn_altered, "endpoint_id", "model-b")
        self.assertNotEqual(turn_original.turn_digest, turn_altered.turn_digest)

    def test_authority_boundary_and_ttl_bound(self):
        with self.assertRaises(TaskRoutingError):
            ledger().admit(lease(), now=20, authority=dict(AUTHORITY, model_output_is_authority=True))
        with self.assertRaises(TaskRoutingError):
            ledger().admit(lease("too-long", expires=500), now=20, authority=AUTHORITY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
