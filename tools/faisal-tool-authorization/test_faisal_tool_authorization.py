#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_tool_authorization import InvocationRequest, ToolAdmissionLedger, ToolAuthorizationError, ToolDescriptor, ToolGrant, digest


def make_descriptor(*, generation: int = 4, risk: str = "high") -> ToolDescriptor:
    return ToolDescriptor("server-1", "send_email", "https://mcp.example.test", digest({"tool": "send_email", "schema": 1}), ("mcp:tools", "email:send"), risk, generation)


def make_grant(descriptor: ToolDescriptor, *, generation: int = 4, max_uses: int = 2, minimum_confirmation: str = "medium") -> ToolGrant:
    return ToolGrant("grant-1", "agent-1", descriptor.resource_uri, descriptor.descriptor_digest, ("mcp:tools", "email:send"), 100, 200, generation, max_uses, digest({"operator": "confirmed", "grant": "grant-1"}), minimum_confirmation)


def make_request(descriptor: ToolDescriptor, grant: ToolGrant, *, invocation: str = "inv-1", requested_scopes: tuple[str, ...] = ("email:send",), requested_at: int = 120, risk: str = "high", confirmation: str | None = None, generation: int = 4) -> InvocationRequest:
    return InvocationRequest(invocation, "agent-1", descriptor.resource_uri, descriptor.tool_name, descriptor.descriptor_digest, requested_scopes, digest({"to": "user@example.test", "body": "approved"}), risk, requested_at, generation, confirmation)


class ToolAuthorizationTests(unittest.TestCase):
    def test_low_risk_admission_matches_resource_descriptor_scope(self) -> None:
        descriptor = make_descriptor(risk="low")
        grant = make_grant(descriptor, minimum_confirmation="low")
        request = make_request(descriptor, grant, risk="low")
        result = ToolAdmissionLedger().admit(descriptor, grant, request, current_generation=4, now=130, nonce="n1")
        self.assertTrue(result["admitted"])
        self.assertFalse(result["authority"]["grant_is_production_authority"])

    def test_high_risk_requires_matching_confirmation(self) -> None:
        descriptor = make_descriptor()
        grant = make_grant(descriptor)
        ledger = ToolAdmissionLedger()
        with self.assertRaises(ToolAuthorizationError):
            ledger.admit(descriptor, grant, make_request(descriptor, grant), current_generation=4, now=130, nonce="n1")
        ok = ledger.admit(descriptor, grant, make_request(descriptor, grant, invocation="inv-2", confirmation=grant.confirmation_digest), current_generation=4, now=130, nonce="n2")
        self.assertTrue(ok["admitted"])

    def test_scope_resource_descriptor_and_actor_fences(self) -> None:
        descriptor = make_descriptor()
        grant = make_grant(descriptor)
        ledger = ToolAdmissionLedger()
        for request in (
            make_request(descriptor, grant, invocation="scope", requested_scopes=("admin:delete",), confirmation=grant.confirmation_digest),
            InvocationRequest("resource", "agent-1", "https://other.example.test", descriptor.tool_name, descriptor.descriptor_digest, ("email:send",), digest({"x": 1}), "high", 120, 4, grant.confirmation_digest),
            InvocationRequest("actor", "agent-2", descriptor.resource_uri, descriptor.tool_name, descriptor.descriptor_digest, ("email:send",), digest({"x": 1}), "high", 120, 4, grant.confirmation_digest),
        ):
            with self.assertRaises(ToolAuthorizationError):
                ledger.admit(descriptor, grant, request, current_generation=4, now=130, nonce=request.invocation_id)

    def test_expiry_generation_and_use_limit_fail_closed(self) -> None:
        descriptor = make_descriptor()
        grant = make_grant(descriptor, max_uses=1)
        ledger = ToolAdmissionLedger()
        good = make_request(descriptor, grant, confirmation=grant.confirmation_digest)
        ledger.admit(descriptor, grant, good, current_generation=4, now=130, nonce="n1")
        with self.assertRaises(ToolAuthorizationError):
            ledger.admit(descriptor, grant, make_request(descriptor, grant, invocation="second", confirmation=grant.confirmation_digest), current_generation=4, now=130, nonce="n2")
        with self.assertRaises(ToolAuthorizationError):
            ToolAdmissionLedger().admit(descriptor, grant, make_request(descriptor, grant, invocation="expired", confirmation=grant.confirmation_digest), current_generation=4, now=200, nonce="n3")
        with self.assertRaises(ToolAuthorizationError):
            ToolAdmissionLedger().admit(descriptor, grant, make_request(descriptor, grant, invocation="stale", confirmation=grant.confirmation_digest, generation=5), current_generation=5, now=130, nonce="n4")

    def test_replay_tamper_and_untrusted_annotations(self) -> None:
        descriptor = make_descriptor(risk="low")
        grant = make_grant(descriptor, minimum_confirmation="low")
        request = make_request(descriptor, grant, risk="low")
        ledger = ToolAdmissionLedger()
        ledger.admit(descriptor, grant, request, current_generation=4, now=130, nonce="n1")
        with self.assertRaises(ToolAuthorizationError):
            ledger.admit(descriptor, grant, request, current_generation=4, now=130, nonce="n2")
        bad_descriptor = copy.copy(descriptor)
        object.__setattr__(bad_descriptor, "annotations_untrusted", False)
        with self.assertRaises(ToolAuthorizationError):
            ToolDescriptor(bad_descriptor.server_id, bad_descriptor.tool_name, bad_descriptor.resource_uri, bad_descriptor.descriptor_digest, bad_descriptor.declared_scopes, bad_descriptor.risk_level, bad_descriptor.generation, False)

    def test_authority_tamper_is_rejected_in_receipt_inputs(self) -> None:
        descriptor = make_descriptor(risk="low")
        grant = make_grant(descriptor, minimum_confirmation="low")
        result = ToolAdmissionLedger().admit(descriptor, grant, make_request(descriptor, grant, risk="low"), current_generation=4, now=130, nonce="n1")
        tampered = copy.deepcopy(result)
        tampered["authority"]["tool_result_is_authority"] = True
        self.assertNotEqual(tampered["receipt_digest"], digest({k: v for k, v in tampered.items() if k != "receipt_digest"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
