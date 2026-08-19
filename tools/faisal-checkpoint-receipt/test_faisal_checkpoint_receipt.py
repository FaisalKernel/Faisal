#!/usr/bin/env python3
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from faisal_checkpoint_receipt import CheckpointContractError, CheckpointInput, CheckpointLedger, SCHEMA, digest


class CheckpointReceiptTests(unittest.TestCase):
    def checkpoint(self, sequence=1, event_sequence=10, previous=None, created_at=100, objective="objective-1", generation=7, lease="lease-1", lease_generation=3):
        return CheckpointInput(
            objective_id=objective,
            execution_generation=generation,
            checkpoint_sequence=sequence,
            lease_id=lease,
            lease_generation=lease_generation,
            trace_digest=digest(f"trace-{sequence}"),
            state_digest=digest(f"state-{sequence}"),
            world_digest=digest(f"world-{sequence}"),
            resource_digest=digest(f"resource-{sequence}"),
            event_sequence=event_sequence,
            event_digest=digest(f"event-{sequence}"),
            previous_checkpoint_digest=previous,
            created_at=created_at,
        )

    def test_first_and_second_checkpoint_chain_verify(self):
        ledger = CheckpointLedger(max_receipts=8, max_objectives=2, max_age_seconds=300)
        first = ledger.record(self.checkpoint(), now=101, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
        self.assertEqual(first["schema"], SCHEMA)
        self.assertTrue(first["verified"])
        second = ledger.record(self.checkpoint(sequence=2, event_sequence=12, previous=first["receipt_digest"], created_at=101), now=102, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
        verified = ledger.verify(second, objective_id="objective-1", expected_execution_generation=7, expected_lease_id="lease-1", expected_lease_generation=3)
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["checkpoint_sequence"], 2)
        self.assertFalse(second["authority"]["model_output_is_authority"])
        self.assertFalse(second["authority"]["checkpoint_is_execution"])

    def test_chain_and_lease_fences_fail_closed(self):
        ledger = CheckpointLedger(max_receipts=8, max_objectives=2, max_age_seconds=300)
        first = ledger.record(self.checkpoint(), now=101, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
        cases = [
            self.checkpoint(sequence=3, event_sequence=12, previous=first["receipt_digest"]),
            self.checkpoint(sequence=2, event_sequence=12, previous=digest("wrong")),
            self.checkpoint(sequence=2, event_sequence=12, previous=first["receipt_digest"], generation=8),
        ]
        for item in cases:
            with self.assertRaises(CheckpointContractError):
                ledger.record(item, now=102, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
        with self.assertRaises(CheckpointContractError):
            ledger.record(self.checkpoint(), now=101, current_execution_generation=7, current_lease_id="lease-2", current_lease_generation=3)

    def test_freshness_tamper_and_resume_replay_fail_closed(self):
        ledger = CheckpointLedger(max_receipts=8, max_objectives=2, max_age_seconds=30)
        first = ledger.record(self.checkpoint(), now=100, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
        with self.assertRaises(CheckpointContractError):
            ledger.record(self.checkpoint(sequence=2, event_sequence=12, previous=first["receipt_digest"], created_at=50), now=100, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
        tampered = copy.deepcopy(first)
        tampered["checkpoint"]["state_digest"] = digest("tampered")
        with self.assertRaises(CheckpointContractError):
            ledger.verify(tampered, objective_id="objective-1", expected_execution_generation=7, expected_lease_id="lease-1", expected_lease_generation=3)
        admitted = ledger.admit_resume(first, objective_id="objective-1", expected_execution_generation=7, expected_lease_id="lease-1", expected_lease_generation=3, resume_nonce="resume-1")
        self.assertTrue(admitted["admitted"])
        self.assertFalse(admitted["resume_is_execution"])
        with self.assertRaises(CheckpointContractError):
            ledger.admit_resume(first, objective_id="objective-1", expected_execution_generation=7, expected_lease_id="lease-1", expected_lease_generation=3, resume_nonce="resume-1")

    def test_profile_does_not_authorize_recovery_and_bounds_are_enforced(self):
        with self.assertRaises(CheckpointContractError):
            CheckpointLedger(max_receipts=0)
        ledger = CheckpointLedger(max_receipts=4, max_objectives=1, max_age_seconds=30)
        first = ledger.record(self.checkpoint(), now=100, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
        with self.assertRaises(CheckpointContractError):
            ledger.verify(first, objective_id="other", expected_execution_generation=7, expected_lease_id="lease-1", expected_lease_generation=3)
        self.assertFalse(first["authority"]["provider_metadata_is_authority"])
        self.assertTrue(first["authority"]["recovery_requires_caller_policy"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
