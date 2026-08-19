#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_task_lifecycle import LifecycleError, TaskEvent, TaskLifecycleAdmission, TaskPolicy


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def handoff(generation: int = 7) -> dict:
    request = {
        "source_agent": "planner",
        "target_agent": "executor",
        "generation": generation,
        "model_authority": False,
        "provider_authority": False,
    }
    body = {"schema": "org.faisal.handoff-receipt.v1", "status": "admitted", "handoff_digest": digest(request), "request": request}
    return body


class TaskLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = TaskPolicy(max_ttl_seconds=300)
        self.admission = TaskLifecycleAdmission()
        self.record = self.admission.admit(handoff(), task_id="task-1", now=100, current_generation=7, expires_at=200, policy=self.policy, nonce="admit")

    def append(self, status: str, trace: int, progress: float, **kwargs: object) -> dict:
        return self.admission.append(self.record, TaskEvent(event_id=f"e-{trace}", status=status, observed_at=100 + trace, trace_position=trace, progress=progress, **kwargs), now=100 + trace, current_generation=7, policy=self.policy, nonce=f"nonce-{trace}")

    def test_running_pause_resume_completion_binds_checkpoint_and_result(self) -> None:
        self.record = self.append("running", 1, 0.2)
        checkpoint = digest({"state": "halfway", "task": "task-1"})
        self.record = self.append("paused", 2, 0.5, checkpoint_digest=checkpoint)
        self.record = self.append("running", 3, 0.5)
        result = digest({"answer": "verified-data"})
        self.record = self.append("completed", 4, 1.0, result_digest=result)
        self.assertTrue(self.admission.verify(self.record, policy=self.policy))
        self.assertEqual(self.record["status"], "completed")
        self.assertFalse(self.record["authority"]["task_is_execution"])

    def test_cancel_requested_requires_cancelled_transition(self) -> None:
        self.record = self.append("running", 1, 0.1)
        self.record = self.append("cancel_requested", 2, 0.1)
        self.record = self.append("cancelled", 3, 0.1, error_code="operator_cancelled")
        self.assertEqual(self.record["status"], "cancelled")
        with self.assertRaises(LifecycleError):
            self.append("running", 4, 0.2)

    def test_missing_checkpoint_and_result_fail_closed(self) -> None:
        with self.assertRaises(LifecycleError):
            self.append("paused", 1, 0.2)
        self.record = self.append("running", 1, 0.2)
        with self.assertRaises(LifecycleError):
            self.append("completed", 2, 1.0)

    def test_scope_generation_ttl_and_authority_fences(self) -> None:
        with self.assertRaises(LifecycleError):
            self.admission.admit(handoff(generation=8), task_id="bad-generation", now=100, current_generation=7, expires_at=200, policy=self.policy, nonce="g1")
        with self.assertRaises(LifecycleError):
            self.admission.admit(handoff(), task_id="bad-expiry", now=100, current_generation=7, expires_at=401, policy=self.policy, nonce="expiry")
        bad = handoff(); bad["request"]["model_authority"] = True
        with self.assertRaises(LifecycleError):
            self.admission.admit(bad, task_id="bad-authority", now=100, current_generation=7, expires_at=200, policy=self.policy, nonce="authority")
        with self.assertRaises(LifecycleError):
            self.admission.append(self.record, TaskEvent("expired", "running", 101, 1, 0.1), now=500, current_generation=7, policy=self.policy, nonce="expired")

    def test_trace_progress_replay_and_checkpoint_fences(self) -> None:
        self.record = self.append("running", 1, 0.5)
        with self.assertRaises(LifecycleError):
            self.append("running", 1, 0.6)
        with self.assertRaises(LifecycleError):
            self.append("running", 2, 0.4)
        checkpoint = digest("checkpoint-a")
        self.record = self.append("paused", 3, 0.6, checkpoint_digest=checkpoint)
        with self.assertRaises(LifecycleError):
            self.append("running", 4, 0.6, checkpoint_digest=checkpoint)

    def test_tampered_record_is_rejected(self) -> None:
        tampered = copy.deepcopy(self.record)
        tampered["progress"] = 0.9
        with self.assertRaises(LifecycleError):
            self.admission.append(tampered, TaskEvent("tamper", "running", 101, 1, 0.1), now=101, current_generation=7, policy=self.policy, nonce="tamper")
        with self.assertRaises(LifecycleError):
            self.admission.verify(tampered, policy=self.policy)

    def test_replay_and_handoff_linkage_are_rejected(self) -> None:
        self.record = self.append("running", 1, 0.1)
        event = TaskEvent("same", "running", 102, 2, 0.2)
        self.record = self.admission.append(self.record, event, now=102, current_generation=7, policy=self.policy, nonce="new")
        with self.assertRaises(LifecycleError):
            self.admission.append(self.record, event, now=102, current_generation=7, policy=self.policy, nonce="new")
        other = self.admission.admit(handoff(), task_id="task-2", now=100, current_generation=7, expires_at=200, policy=self.policy, nonce="other")
        wrong_link = copy.deepcopy(other)
        wrong_link["handoff_digest"] = digest("different-handoff")
        with self.assertRaises(LifecycleError):
            self.admission.append(wrong_link, TaskEvent("wrong", "running", 101, 1, 0.1), now=101, current_generation=7, policy=self.policy, nonce="wrong")


if __name__ == "__main__":
    unittest.main(verbosity=2)
