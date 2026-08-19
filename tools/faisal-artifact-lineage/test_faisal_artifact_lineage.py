from __future__ import annotations

import copy
import unittest

from faisal_artifact_lineage import (
    ArtifactLineageError,
    ArtifactLineageLedger,
    ArtifactSnapshot,
    LineagePolicy,
    RefinementRequest,
    TaskSnapshot,
    digest,
)

AUTHORITY = {
    "model_output_is_authority": False,
    "artifact_content_is_authority": False,
    "agent_output_is_authority": False,
    "acceptance_evidence_is_execution_authority": False,
    "lineage_receipt_is_policy_authority": False,
    "lineage_receipt_is_production_authority": False,
}


def policy():
    return LineagePolicy("lineage-policy", "v1", 7, ("tenant-a", "project-a", "agent-a"), max_depth=8, max_ttl=120)


def task(task_id="task-parent", state="completed", expires=100):
    return TaskSnapshot(task_id, "context-a", "tenant-a", state, 7, digest({"task": task_id}), 10, expires)


def artifact(artifact_id="artifact-v1", state="accepted", version=1, depth=1, expires=100):
    return ArtifactSnapshot(artifact_id, "report.json", "task-parent", "context-a", "tenant-a", digest({"artifact": artifact_id}), None, version, depth, state, 7, 10, expires, ("tenant-a", "project-a"))


def request(parent_artifact, refinement_id="refine-1", child_task="task-child", context="context-a", version=2, acceptance=True, scope_value=("tenant-a", "project-a"), expires=90):
    return RefinementRequest(refinement_id, "task-parent", parent_artifact.artifact_id, parent_artifact.artifact_digest, child_task, context, "artifact-v2", digest({"child": refinement_id}), "report.json", version, tuple(scope_value), 7, 20, expires, digest({"accept": refinement_id}) if acceptance else None, "nonce-" + refinement_id)


def ledger():
    l = ArtifactLineageLedger(policy())
    l.register_task(task())
    l.register_artifact(artifact())
    return l


class ArtifactLineageTests(unittest.TestCase):
    def test_valid_refinement_is_immutable_and_monotonic(self):
        result = ledger().admit_refinement(request(artifact()), now=21, authority=AUTHORITY)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["parent_version"], 1)
        self.assertEqual(result["child_version"], 2)
        self.assertFalse(result["task_created"])
        self.assertFalse(result["artifact_mutated"])

    def test_terminal_task_and_artifact_state_required(self):
        active = ArtifactLineageLedger(policy())
        active.register_task(task(state="active")); active.register_artifact(artifact())
        with self.assertRaises(ArtifactLineageError):
            active.admit_refinement(request(artifact()), now=21, authority=AUTHORITY)
        provisional = ArtifactLineageLedger(policy())
        provisional.register_task(task()); provisional.register_artifact(artifact(state="provisional"))
        with self.assertRaises(ArtifactLineageError):
            provisional.admit_refinement(request(artifact()), now=21, authority=AUTHORITY)

    def test_context_scope_version_and_acceptance_fences(self):
        l = ledger(); parent = artifact()
        with self.assertRaises(ArtifactLineageError):
            l.admit_refinement(request(parent, refinement_id="context", context="other-context"), now=21, authority=AUTHORITY)
        with self.assertRaises(ArtifactLineageError):
            l.admit_refinement(request(parent, refinement_id="scope", scope_value=("tenant-a", "agent-a")), now=21, authority=AUTHORITY)
        with self.assertRaises(ArtifactLineageError):
            l.admit_refinement(request(parent, refinement_id="version", version=3), now=21, authority=AUTHORITY)
        with self.assertRaises(ArtifactLineageError):
            l.admit_refinement(request(parent, refinement_id="acceptance", acceptance=False), now=21, authority=AUTHORITY)

    def test_generation_expiry_and_replay(self):
        l = ledger(); parent = artifact()
        with self.assertRaises(ArtifactLineageError):
            l.admit_refinement(RefinementRequest("generation", "task-parent", parent.artifact_id, parent.artifact_digest, "task-child", "context-a", "artifact-v2", digest({"child": "generation"}), "report.json", 2, ("tenant-a", "project-a"), 8, 20, 90, digest({"a": 1}), "nonce-generation"), now=21, authority=AUTHORITY)
        with self.assertRaises(ArtifactLineageError):
            l.admit_refinement(request(parent, refinement_id="expiry", expires=21), now=21, authority=AUTHORITY)
        l.admit_refinement(request(parent), now=21, authority=AUTHORITY)
        with self.assertRaises(ArtifactLineageError):
            l.admit_refinement(request(parent), now=22, authority=AUTHORITY)

    def test_tamper_and_authority_boundaries(self):
        parent = artifact()
        altered = copy.copy(parent)
        object.__setattr__(altered, "artifact_digest", digest({"tampered": True}))
        self.assertNotEqual(parent.snapshot_digest, altered.snapshot_digest)
        with self.assertRaises(ArtifactLineageError):
            ledger().admit_refinement(request(parent, refinement_id="authority"), now=21, authority=dict(AUTHORITY, model_output_is_authority=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
