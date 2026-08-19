#!/usr/bin/env python3
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from faisal_memory_write_gate import MemoryCandidate, MemoryWriteError, MemoryWriteGate, MemoryWritePolicy, VerificationReceipt, digest


class MemoryWriteGateTests(unittest.TestCase):
    def candidate(self, *, memory_class="working", source_kind="verified_tool", trust="bounded", verification="verified", injection=False, created=100, expires=500, generation=7, scope=("agent:1",)):
        return MemoryCandidate(
            memory_id="memory-1",
            memory_class=memory_class,
            source_kind=source_kind,
            source_id="source-1",
            source_digest=digest("source"),
            content_digest=digest(f"content-{memory_class}-{source_kind}-{injection}"),
            provenance_digest=digest("provenance"),
            scope=scope,
            trust=trust,
            verification=verification,
            generation=generation,
            created_at=created,
            expires_at=expires,
            injection_signaled=injection,
        )

    def policy(self, *, allow_quarantine=True, max_age=300):
        return MemoryWritePolicy(allowed_scope=("agent:1", "team:research"), minimum_trust="bounded", minimum_verification="verified", allow_quarantine=allow_quarantine, max_age_seconds=max_age)

    def test_verified_bounded_tool_write_is_admitted(self):
        gate = MemoryWriteGate(max_entries=8)
        result = gate.admit(self.candidate(), policy=self.policy(), now=110, current_generation=7, nonce="n1")
        self.assertTrue(result["admitted"])
        self.assertFalse(result["quarantined"])
        self.assertFalse(result["authority"]["provider_metadata_is_authority"])

    def test_model_browser_and_injection_content_is_quarantined(self):
        gate = MemoryWriteGate(max_entries=8)
        for index, candidate in enumerate((self.candidate(source_kind="model_output", trust="untrusted", verification="unverified"), self.candidate(source_kind="browser_observation", trust="untrusted", verification="unverified", injection=True)), start=1):
            result = gate.admit(candidate, policy=self.policy(), now=110, current_generation=7, nonce=f"n{index}")
            self.assertFalse(result["admitted"])
            self.assertTrue(result["quarantined"])
            self.assertEqual(result["status"], "quarantined")

    def test_explicit_verified_promotion_is_admitted(self):
        gate = MemoryWriteGate(max_entries=8)
        quarantined = gate.admit(self.candidate(memory_class="semantic", source_kind="model_output", trust="untrusted", verification="unverified"), policy=self.policy(), now=110, current_generation=7, nonce="n1")
        verification = VerificationReceipt(candidate_digest=quarantined["candidate_digest"], verifier_id="verifier-1", evidence_digest=digest("evidence"), generation=7, verified_at=120)
        promoted = gate.promote(quarantined, verification=verification, policy=self.policy(), now=121, current_generation=7, nonce="promote-1")
        self.assertTrue(promoted["admitted"])
        self.assertFalse(promoted["quarantined"])
        self.assertEqual(promoted["reason"], "explicit_verified_promotion")
        with self.assertRaises(MemoryWriteError):
            gate.promote(quarantined, verification=verification, policy=self.policy(), now=121, current_generation=7, nonce="promote-1")

    def test_scope_generation_expiry_and_replay_fail_closed(self):
        gate = MemoryWriteGate(max_entries=8)
        with self.assertRaises(MemoryWriteError):
            gate.admit(self.candidate(scope=("agent:2",)), policy=self.policy(), now=110, current_generation=7, nonce="scope")
        with self.assertRaises(MemoryWriteError):
            gate.admit(self.candidate(generation=8), policy=self.policy(), now=110, current_generation=7, nonce="generation")
        with self.assertRaises(MemoryWriteError):
            gate.admit(self.candidate(created=1, expires=10), policy=self.policy(max_age=50), now=110, current_generation=7, nonce="stale")
        first = gate.admit(self.candidate(), policy=self.policy(), now=110, current_generation=7, nonce="replay")
        with self.assertRaises(MemoryWriteError):
            gate.admit(self.candidate(), policy=self.policy(), now=110, current_generation=7, nonce="replay-again")
        tampered = copy.deepcopy(first)
        tampered["candidate"]["scope"] = ["agent:2"]
        with self.assertRaises(MemoryWriteError):
            gate.promote(tampered, verification=VerificationReceipt(candidate_digest=first["candidate_digest"], verifier_id="v", evidence_digest=digest("e"), generation=7, verified_at=111), policy=self.policy(), now=112, current_generation=7, nonce="tamper")

    def test_quarantine_can_be_disabled_and_authority_is_never_granted(self):
        gate = MemoryWriteGate(max_entries=4)
        with self.assertRaises(MemoryWriteError):
            gate.admit(self.candidate(source_kind="tool_metadata", trust="untrusted", verification="unverified"), policy=self.policy(allow_quarantine=False), now=110, current_generation=7, nonce="no-quarantine")
        self.assertFalse(gate.admit(self.candidate(), policy=self.policy(), now=110, current_generation=7, nonce="ok")["authority"]["memory_is_policy_authority"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
