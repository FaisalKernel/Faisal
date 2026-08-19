#!/usr/bin/env python3
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from faisal_handoff_receipt import HandoffAdmission, HandoffError, HandoffPolicy, HandoffRequest, HandoffResult, digest


class HandoffReceiptTests(unittest.TestCase):
    def request(self, *, approval="caller_approved", source_trust="bounded", scope=("research:read",), generation=7, issued=100, expires=500, model_authority=False):
        return HandoffRequest(handoff_id="handoff-1", issuer_agent_id="agent-a", delegatee_agent_id="agent-b", objective_digest=digest("objective"), parent_delegation_digest=digest("parent-delegation"), capability_scope=scope, trace_position=12, generation=generation, issued_at=issued, expires_at=expires, approval=approval, source_trust=source_trust, model_output_authority=model_authority)

    def policy(self, *, minimum_approval="caller_approved", operator_scope=()):
        return HandoffPolicy(allowed_scope=("research:read", "research:write", "deploy:staging"), minimum_trust="bounded", minimum_approval=minimum_approval, require_operator_for_scope=operator_scope, max_ttl_seconds=300)

    def result(self, handoff_digest, *, source_kind="delegatee", source_trust="bounded", generation=7, trace=13, observed=120, provider_authority=False):
        return HandoffResult(handoff_digest=handoff_digest, result_digest=digest(f"result-{source_kind}-{trace}"), result_provenance_digest=digest("result-provenance"), source_kind=source_kind, source_trust=source_trust, generation=generation, trace_position=trace, observed_at=observed, provider_metadata_authority=provider_authority)

    def test_admitted_handoff_is_bound_and_non_authoritative(self):
        admission = HandoffAdmission(max_handoffs=8)
        record = admission.admit(self.request(), policy=self.policy(), now=110, current_generation=7, nonce="n1")
        self.assertTrue(record["admitted"])
        self.assertTrue(record["verified"])
        self.assertFalse(record["authority"]["handoff_is_execution"])
        self.assertFalse(record["authority"]["model_output_is_authority"])

    def test_operator_scope_requires_operator_approval(self):
        admission = HandoffAdmission(max_handoffs=8)
        with self.assertRaises(HandoffError):
            admission.admit(self.request(scope=("deploy:staging",)), policy=self.policy(operator_scope=("deploy:staging",)), now=110, current_generation=7, nonce="bad")
        record = admission.admit(self.request(approval="operator_approved", scope=("deploy:staging",)), policy=self.policy(operator_scope=("deploy:staging",)), now=110, current_generation=7, nonce="good")
        self.assertTrue(record["admitted"])

    def test_remote_model_result_is_quarantined(self):
        admission = HandoffAdmission(max_handoffs=8)
        handoff = admission.admit(self.request(), policy=self.policy(), now=110, current_generation=7, nonce="h")
        result = admission.admit_result(handoff, self.result(handoff["handoff_digest"], source_kind="model_output", source_trust="untrusted"), policy=self.policy(), now=121, current_generation=7, nonce="r")
        self.assertFalse(result["admitted"])
        self.assertTrue(result["quarantined"])
        self.assertFalse(result["authority"]["remote_result_is_authority"])

    def test_verified_remote_result_is_admitted_and_replay_rejected(self):
        admission = HandoffAdmission(max_handoffs=8)
        handoff = admission.admit(self.request(), policy=self.policy(), now=110, current_generation=7, nonce="h")
        result = self.result(handoff["handoff_digest"])
        admitted = admission.admit_result(handoff, result, policy=self.policy(), now=121, current_generation=7, nonce="r")
        self.assertTrue(admitted["admitted"])
        with self.assertRaises(HandoffError):
            admission.admit_result(handoff, result, policy=self.policy(), now=121, current_generation=7, nonce="r")

    def test_scope_generation_ttl_trace_and_authority_fail_closed(self):
        admission = HandoffAdmission(max_handoffs=16)
        cases = (
            (self.request(scope=("admin:root",)), self.policy(), 110, "scope"),
            (self.request(generation=8), self.policy(), 110, "generation"),
            (self.request(issued=1, expires=10), self.policy(), 110, "freshness"),
            (self.request(model_authority=True), self.policy(), 110, "authority"),
        )
        for request, policy, now, name in cases:
            with self.subTest(name=name):
                with self.assertRaises(HandoffError):
                    admission.admit(request, policy=policy, now=now, current_generation=7, nonce=name)
        good = admission.admit(self.request(), policy=self.policy(), now=110, current_generation=7, nonce="good")
        with self.assertRaises(HandoffError):
            admission.admit_result(good, self.result(good["handoff_digest"], trace=11), policy=self.policy(), now=121, current_generation=7, nonce="trace")
        with self.assertRaises(HandoffError):
            admission.admit_result(good, self.result(good["handoff_digest"], provider_authority=True), policy=self.policy(), now=121, current_generation=7, nonce="authority-result")

    def test_tampered_handoff_and_result_linkage_fail_closed(self):
        admission = HandoffAdmission(max_handoffs=8)
        record = admission.admit(self.request(), policy=self.policy(), now=110, current_generation=7, nonce="h")
        tampered = copy.deepcopy(record)
        tampered["request"]["capability_scope"] = ["deploy:staging"]
        with self.assertRaises(HandoffError):
            admission.admit_result(tampered, self.result(record["handoff_digest"]), policy=self.policy(), now=121, current_generation=7, nonce="tamper")
        with self.assertRaises(HandoffError):
            admission.admit_result(record, self.result(digest("other")), policy=self.policy(), now=121, current_generation=7, nonce="link")


if __name__ == "__main__":
    unittest.main(verbosity=2)
