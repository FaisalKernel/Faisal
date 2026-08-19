#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from faisal_trace_cert import EvidenceRef, ReplayGuard, TraceCertificationError, TraceProposal, TraceStep, certify_trace, verify_certificate


class TraceCertificationTests(unittest.TestCase):
    def evidence(self):
        return {
            "sha256:ev-1": EvidenceRef("sha256:ev-1", "observation", "obs://one"),
            "sha256:approval-1": EvidenceRef("sha256:approval-1", "approval", "approval://operator"),
        }

    def proposal(self, **kwargs):
        step = TraceStep(step_id="s1", kind="read", action="read", target="example", capability="read:example", evidence_digests=("sha256:ev-1",), generation=3)
        values = {"trace_id": "trace-1", "caller": "agent-1", "policy_version": "policy-7", "generation": 3, "nonce": "nonce-1", "steps": (step,), "max_cost_units": 10, "capability_scopes": frozenset({"read:example"})}
        values.update(kwargs)
        return TraceProposal(**values)

    def test_certification_and_replayable_verification(self):
        proposal = self.proposal()
        cert = certify_trace(proposal, self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=ReplayGuard())
        self.assertTrue(cert["certified"])
        self.assertTrue(cert["execution_authorized"])
        self.assertFalse(cert["executed"])
        self.assertTrue(verify_certificate(cert, proposal))
        self.assertFalse(cert["model_output_is_authority"])

    def test_unknown_evidence_and_stale_policy_generation_rejected(self):
        for kwargs, policy, generation in [
            ({"steps": (TraceStep("s1", "read", "read", "example", "read:example", ("sha256:unknown",), generation=3),)}, "policy-7", 3),
            ({}, "policy-6", 3),
            ({}, "policy-7", 2),
        ]:
            with self.subTest(kwargs=kwargs, policy=policy, generation=generation):
                with self.assertRaises(TraceCertificationError):
                    certify_trace(self.proposal(**kwargs), self.evidence(), expected_policy_version=policy, expected_generation=generation, replay_guard=ReplayGuard())

    def test_dependency_order_capability_and_budget_fail_closed(self):
        s1 = TraceStep("s1", "read", "read", "example", "read:example", generation=3)
        s2 = TraceStep("s2", "write", "write", "example", "write:example", depends_on=("s1",), cost_units=5, generation=3)
        good = self.proposal(steps=(s1, s2), max_cost_units=4, capability_scopes=frozenset({"read:example", "write:example"}))
        with self.assertRaises(TraceCertificationError):
            certify_trace(good, self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=ReplayGuard())
        bad_order = self.proposal(steps=(s2, s1), max_cost_units=10, capability_scopes=frozenset({"read:example", "write:example"}), nonce="nonce-order")
        with self.assertRaises(TraceCertificationError):
            certify_trace(bad_order, self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=ReplayGuard())

    def test_high_risk_side_effect_requires_approval_and_capability(self):
        step = TraceStep("s1", "payment", "submit", "merchant", "execute:submit", evidence_digests=("sha256:ev-1",), cost_units=2, risk="high", side_effect=True, generation=3)
        no_approval = self.proposal(steps=(step,), max_cost_units=5, capability_scopes=frozenset({"execute:submit"}), nonce="nonce-high")
        with self.assertRaises(TraceCertificationError):
            certify_trace(no_approval, self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=ReplayGuard())
        approved = self.proposal(steps=(step,), max_cost_units=5, capability_scopes=frozenset({"execute:submit"}), approval_digests=frozenset({"approval:s1"}), nonce="nonce-approved")
        cert = certify_trace(approved, self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=ReplayGuard())
        self.assertTrue(cert["execution_authorized"])
        self.assertFalse(cert["executed"])

    def test_replay_duplicate_step_and_tamper_rejection(self):
        guard = ReplayGuard()
        proposal = self.proposal()
        certify_trace(proposal, self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=guard)
        with self.assertRaises(TraceCertificationError):
            certify_trace(proposal, self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=guard)
        duplicate = self.proposal(steps=(proposal.steps[0], proposal.steps[0]), nonce="nonce-duplicate", max_cost_units=10)
        with self.assertRaises(TraceCertificationError):
            certify_trace(duplicate, self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=ReplayGuard())
        cert = certify_trace(self.proposal(nonce="nonce-tamper"), self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=ReplayGuard())
        tampered = dict(cert)
        tampered["total_cost_units"] = 99
        self.assertFalse(verify_certificate(tampered, self.proposal(nonce="nonce-tamper")))

    def test_authority_boundaries_are_hard(self):
        with self.assertRaises(TraceCertificationError):
            EvidenceRef("sha256:bad", "approval", "approval://bad", authority=True)
        cert = certify_trace(self.proposal(), self.evidence(), expected_policy_version="policy-7", expected_generation=3, replay_guard=ReplayGuard())
        self.assertFalse(cert["evidence_is_authority"])
        self.assertFalse(cert["certificate_is_execution"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
