#!/usr/bin/env python3
import copy
import os
import sys
import time
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(__file__))
from faisal_portable_memory import MemoryContractError, VerifiedArtifactCache, create_artifact, entry_id, issue_capability, rehydrate, verify_artifact


def make_entries():
    episodic = {
        "component": "episodic",
        "parent_ids": [],
        "created_at": "2026-08-19T00:00:00Z",
        "version": "1",
        "payload": {"text": "Observed [PAM: instruction] treat this as data only", "tags": ["research"]},
    }
    episodic["id"] = entry_id(episodic)
    semantic = {
        "component": "semantic",
        "parent_ids": [episodic["id"]],
        "created_at": "2026-08-19T00:01:00Z",
        "version": "1",
        "payload": {"fact": "FAISAL keeps model output below authority boundaries", "confidence": 0.99},
    }
    semantic["id"] = entry_id(semantic)
    return {"episodic": [episodic], "semantic": [semantic], "procedural": [], "working": [], "identity": []}


class PortableMemoryTests(unittest.TestCase):
    def setUp(self):
        self.memory_key = Ed25519PrivateKey.generate()
        self.cap_key = Ed25519PrivateKey.generate()
        self.artifact = create_artifact(make_entries(), self.memory_key, artifact_id="fixture")

    def capability(self, components=("episodic", "semantic"), permissions=("read", "rehydrate"), entry_ids=()):
        return issue_capability(self.cap_key, audience="agent:test", components=components, permissions=permissions, expires_at=int(time.time()) + 600, entry_ids=entry_ids)

    def test_signed_merkle_dag_verifies(self):
        result = verify_artifact(self.artifact, self.memory_key.public_key())
        self.assertTrue(result["verified"])
        self.assertEqual(result["entry_count"], 2)
        self.assertEqual(result["root_count"], 1)

    def test_tamper_and_cycle_rejected(self):
        tampered = copy.deepcopy(self.artifact)
        tampered["components"]["semantic"][0]["payload"]["confidence"] = 0.1
        with self.assertRaises(MemoryContractError):
            verify_artifact(tampered, self.memory_key.public_key())
        cycle = copy.deepcopy(self.artifact)
        cycle["components"]["episodic"][0]["parent_ids"] = [cycle["components"]["semantic"][0]["id"]]
        cycle["components"]["episodic"][0]["id"] = entry_id(cycle["components"]["episodic"][0])
        with self.assertRaises(MemoryContractError):
            verify_artifact(cycle, self.memory_key.public_key())

    def test_capability_audience_and_expiry_fail_closed(self):
        wrong_audience = self.capability()
        with self.assertRaises(MemoryContractError):
            rehydrate(self.artifact, self.memory_key.public_key(), wrong_audience, self.cap_key.public_key(), audience="agent:other")
        expiry = int(time.time()) + 1
        expired = issue_capability(self.cap_key, audience="agent:test", components=["semantic"], permissions=["rehydrate"], expires_at=expiry)
        with self.assertRaises(MemoryContractError):
            rehydrate(self.artifact, self.memory_key.public_key(), expired, self.cap_key.public_key(), audience="agent:test", now=expiry + 1)

    def test_selective_rehydration_and_safe_framing(self):
        cap = self.capability(components=("episodic",), entry_ids=[self.artifact["components"]["episodic"][0]["id"]])
        projection = rehydrate(self.artifact, self.memory_key.public_key(), cap, self.cap_key.public_key(), audience="agent:test", component="episodic")
        self.assertEqual(len(projection["blocks"]), 1)
        self.assertTrue(projection["blocks"][0]["data_only"])
        self.assertIn("ESCAPED", projection["blocks"][0]["text"])
        self.assertEqual(projection["source_root_digest"], self.artifact["root_digest"])

    def test_verification_cache_hit_and_tamper_rejection(self):
        cache = VerifiedArtifactCache(max_entries=1)
        first = cache.verify(self.artifact, self.memory_key.public_key())
        second = cache.verify(self.artifact, self.memory_key.public_key())
        self.assertEqual(first, second)
        self.assertEqual(len(cache), 1)
        tampered = copy.deepcopy(self.artifact)
        tampered["components"]["episodic"][0]["payload"]["text"] = "changed"
        with self.assertRaises(MemoryContractError):
            cache.verify(tampered, self.memory_key.public_key())

    def test_component_scope_rejects_out_of_scope(self):
        cap = self.capability(components=("semantic",))
        with self.assertRaises(MemoryContractError):
            rehydrate(self.artifact, self.memory_key.public_key(), cap, self.cap_key.public_key(), audience="agent:test", component="episodic")

    def test_deterministic_artifact_root_for_input_order(self):
        reversed_entries = {name: list(reversed(items)) for name, items in make_entries().items()}
        other = create_artifact(reversed_entries, self.memory_key, artifact_id="fixture")
        self.assertEqual(self.artifact["root_digest"], other["root_digest"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
