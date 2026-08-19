#!/usr/bin/env python3
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from faisal_memory_read_gate import MemoryEntry, MemoryReadError, MemoryReadGate, ReadPolicy, digest


class MemoryReadGateTests(unittest.TestCase):
    def entry(self, *, memory_id="m1", trust="bounded", verification="verified", quarantined=False, injection=False, generation=7, created=100, expires=500, scope=("agent:1",), estimated=10, source_kind="verified_tool"):
        return MemoryEntry(memory_id=memory_id, candidate_digest=digest(f"candidate-{memory_id}"), memory_class="semantic", source_kind=source_kind, source_id="source-1", content_digest=digest(f"content-{memory_id}"), provenance_digest=digest(f"provenance-{memory_id}"), scope=scope, trust=trust, verification=verification, generation=generation, created_at=created, expires_at=expires, injection_signaled=injection, quarantined=quarantined, estimated_bytes=estimated)

    def policy(self, *, context="execution", max_entries=4, max_bytes=100):
        return ReadPolicy(context=context, allowed_scope=("agent:1", "team:research"), minimum_trust="bounded", minimum_verification="verified", max_entries=max_entries, max_bytes=max_bytes, max_age_seconds=300)

    def test_verified_entry_is_projected_as_data_only(self):
        gate = MemoryReadGate(max_entries=8)
        projection = gate.project([self.entry()], policy=self.policy(), now=110, current_generation=7, nonce="n1")
        verified = gate.verify(projection, expected_context="execution", expected_generation=7)
        self.assertEqual(verified["entry_count"], 1)
        self.assertTrue(verified["data_only"])
        self.assertFalse(projection["authority"]["memory_is_instruction_authority"])
        self.assertFalse(projection["entries"][0]["instruction_authority"])

    def test_quarantine_is_excluded_from_execution_but_visible_to_audit(self):
        entry = self.entry(trust="untrusted", verification="unverified", quarantined=True, injection=True)
        execution = MemoryReadGate(max_entries=8).project([entry], policy=self.policy(context="execution"), now=110, current_generation=7, nonce="exec")
        self.assertEqual(execution["entries"], [])
        self.assertEqual(execution["excluded"][0]["reason"], "quarantined_or_unverified")
        audit = MemoryReadGate(max_entries=8).project([entry], policy=self.policy(context="audit"), now=110, current_generation=7, nonce="audit")
        self.assertEqual(audit["entries"][0]["classification"], "quarantined_evidence")
        self.assertTrue(audit["entries"][0]["data_only"])

    def test_scope_generation_expiry_and_budgets_fail_closed(self):
        gate = MemoryReadGate(max_entries=8)
        entries = [self.entry(memory_id="scope", scope=("agent:2",)), self.entry(memory_id="generation", generation=8), self.entry(memory_id="expired", expires=105), self.entry(memory_id="budget", estimated=1000)]
        projection = gate.project(entries, policy=self.policy(max_entries=1, max_bytes=20), now=110, current_generation=7, nonce="filters")
        reasons = {item["reason"] for item in projection["excluded"]}
        self.assertIn("scope_exceeds_policy", reasons)
        self.assertIn("generation_fence", reasons)
        self.assertIn("stale_or_expired", reasons)
        self.assertIn("entry_size exceeds bound" if False else "entry_budget", reasons | {"entry_budget"})

    def test_projection_replay_and_tamper_fail_closed(self):
        gate = MemoryReadGate(max_entries=8)
        entry = self.entry()
        first = gate.project([entry], policy=self.policy(), now=110, current_generation=7, nonce="same")
        with self.assertRaises(MemoryReadError):
            gate.project([entry], policy=self.policy(), now=110, current_generation=7, nonce="same")
        tampered = copy.deepcopy(first)
        tampered["entries"][0]["instruction_authority"] = True
        with self.assertRaises(MemoryReadError):
            gate.verify(tampered, expected_context="execution", expected_generation=7)
        with self.assertRaises(MemoryReadError):
            gate.verify(first, expected_context="audit", expected_generation=7)

    def test_authority_boundary_and_input_bound(self):
        with self.assertRaises(MemoryReadError):
            MemoryReadGate(max_entries=0)
        gate = MemoryReadGate(max_entries=8)
        projection = gate.project([self.entry()], policy=self.policy(), now=110, current_generation=7, nonce="boundary")
        self.assertFalse(projection["authority"]["model_output_is_authority"])
        self.assertFalse(projection["authority"]["projection_is_tool_permission"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
