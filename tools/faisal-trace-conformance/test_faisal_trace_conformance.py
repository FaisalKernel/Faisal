#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../faisal-trace-cert"))
from faisal_trace_cert import EvidenceRef, ReplayGuard, TraceProposal, TraceStep, certify_trace
from faisal_trace_conformance import RealizedStep, TraceConformanceError, build_receipt_chain, verify_conformance, verify_receipt_chain


class TraceConformanceTests(unittest.TestCase):
    def proposal_and_certificate(self):
        evidence = {"sha256:obs": EvidenceRef("sha256:obs", "observation", "obs://conformance")}
        s1 = TraceStep("s1", "read", "read", "example", "read:example", ("sha256:obs",), cost_units=1, generation=5)
        s2 = TraceStep("s2", "transform", "transform", "local", "transform:local", ("sha256:obs",), depends_on=("s1",), cost_units=1, generation=5)
        proposal = TraceProposal("trace-conformance", "agent-1", "policy-10", 5, "conformance-nonce", (s1, s2), 5, frozenset({"read:example", "transform:local"}))
        certificate = certify_trace(proposal, evidence, expected_policy_version="policy-10", expected_generation=5, replay_guard=ReplayGuard())
        return proposal, certificate

    def realized(self, status="completed", failure=None):
        return [
            RealizedStep("s1", "read", "example", "read:example", "completed", "sha256:" + "1" * 64, generation=5),
            RealizedStep("s2", "transform", "local", "transform:local", status, "sha256:" + "2" * 64 if status == "completed" else None, failure, 5),
        ]

    def test_complete_conformance_and_receipt_chain(self):
        proposal, certificate = self.proposal_and_certificate()
        result = verify_conformance(proposal, certificate, self.realized(), expected_generation=5)
        self.assertEqual(result["conformance"], "complete")
        self.assertTrue(result["completion"])
        self.assertFalse(result["result_correctness"])
        self.assertTrue(verify_receipt_chain(proposal, result["receipt_chain"]))
        self.assertFalse(result["executed_by_this_module"])

    def test_failure_halts_without_completion(self):
        proposal, certificate = self.proposal_and_certificate()
        result = verify_conformance(proposal, certificate, self.realized(status="failed", failure="TOOL_TIMEOUT"), expected_generation=5)
        self.assertEqual(result["conformance"], "halt_required")
        self.assertFalse(result["completion"])
        self.assertEqual(result["next_action"], "halt_rollback_or_escalate")

    def test_incomplete_trace_does_not_complete(self):
        proposal, certificate = self.proposal_and_certificate()
        result = verify_conformance(proposal, certificate, self.realized()[:1], expected_generation=5)
        self.assertEqual(result["conformance"], "incomplete")
        self.assertFalse(result["completion"])
        self.assertEqual(result["next_action"], "do_not_complete_resume_or_escalate")

    def test_extra_reordered_and_mismatched_steps_rejected(self):
        proposal, certificate = self.proposal_and_certificate()
        extra = self.realized() + [RealizedStep("s3", "x", "x", "x", "completed", "sha256:" + "3" * 64, generation=5)]
        reordered = list(reversed(self.realized()))
        mismatched = [RealizedStep("s1", "write", "example", "read:example", "completed", "sha256:" + "1" * 64, generation=5), self.realized()[1]]
        for candidate in (extra, reordered, mismatched):
            with self.assertRaises(TraceConformanceError):
                verify_conformance(proposal, certificate, candidate, expected_generation=5)

    def test_generation_and_certificate_fencing(self):
        proposal, certificate = self.proposal_and_certificate()
        stale = self.realized()
        stale[1] = RealizedStep("s2", "transform", "local", "transform:local", "completed", "sha256:" + "2" * 64, generation=4)
        with self.assertRaises(TraceConformanceError):
            verify_conformance(proposal, certificate, stale, expected_generation=5)
        tampered = dict(certificate)
        tampered["proposal_digest"] = "sha256:" + "f" * 64
        with self.assertRaises(TraceConformanceError):
            verify_conformance(proposal, tampered, self.realized(), expected_generation=5)

    def test_receipt_chain_tamper_and_reorder_rejected(self):
        proposal, _ = self.proposal_and_certificate()
        chain = build_receipt_chain(proposal, self.realized())
        self.assertTrue(verify_receipt_chain(proposal, chain))
        tampered = [dict(x) for x in chain]
        tampered[1]["step"] = dict(tampered[1]["step"])
        tampered[1]["step"]["result_digest"] = "sha256:" + "f" * 64
        self.assertFalse(verify_receipt_chain(proposal, tampered))
        self.assertFalse(verify_receipt_chain(proposal, list(reversed(chain))))

    def test_invalid_realized_step_rejected(self):
        with self.assertRaises(TraceConformanceError):
            RealizedStep("s1", "read", "example", "read:example", "completed", None, generation=5)
        with self.assertRaises(TraceConformanceError):
            RealizedStep("s1", "read", "example", "read:example", "failed", None, None, generation=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
