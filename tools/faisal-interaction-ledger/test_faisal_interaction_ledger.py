from __future__ import annotations

import unittest

from faisal_interaction_ledger import InteractionLedger, InteractionLedgerError, LedgerPolicy, LedgerRequest, SegmentAnchor, TerminalVerification, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "telemetry_is_kernel_ground_truth": False,
    "span_content_is_truth": False,
    "ledger_receipt_is_execution_authority": False,
    "ledger_receipt_is_policy_authority": False,
    "ledger_receipt_is_production_authority": False,
}
CAP = digest({"manifest": "m1"})
DELEGATION = digest({"chain": "d1"})
ROUTE = digest({"route": "r1"})


def policy():
    return LedgerPolicy("ledger-policy", "v1", 7, "audience-tools", max_ttl=120, max_spans=8)


def segment(segment_id, sequence, parent=None, span=None, trace="trace-1", task="task-1", artifact="artifact-1"):
    return SegmentAnchor(segment_id, trace, task, artifact, CAP, DELEGATION, ROUTE, "audience-tools", 7, policy().policy_digest, sequence, parent, digest({"span": span or segment_id}), 10 + sequence, 100)


def terminal(segment_id="seg-2", terminal_id="term-1", verified=True):
    return TerminalVerification(terminal_id, segment_id, digest({"result": "ok"}), verified, "verifier-a", 30, "completed", replay_performed=False)


def request(ledger, segments, request_id="req-1", with_terminal=True, first=1, last=2, expires=80):
    return LedgerRequest(request_id, "trace-1", "task-1", "artifact-1", CAP, DELEGATION, ROUTE, "audience-tools", 7, policy().policy_digest, "seg-2", first, last, tuple(x.segment_digest for x in segments), terminal() if with_terminal else None, 20, expires, "nonce-" + request_id)


class InteractionLedgerTests(unittest.TestCase):
    def test_valid_ordered_terminal_commitment(self):
        ledger = InteractionLedger(policy())
        first = segment("seg-1", 1)
        first_digest = ledger.append(first)
        second = segment("seg-2", 2, first_digest)
        ledger.append(second)
        result = ledger.admit(request(ledger, [first, second]), now=31, authority=AUTHORITY)
        self.assertTrue(result["terminal_verified"])
        self.assertEqual(result["segment_count"], 2)
        self.assertFalse(result["raw_content_stored"])
        self.assertFalse(result["tools_executed"])

    def test_sequence_gap_and_parent_tamper(self):
        ledger = InteractionLedger(policy())
        first_digest = ledger.append(segment("gap-1", 1, trace="trace-gap"))
        with self.assertRaises(InteractionLedgerError):
            ledger.append(segment("gap-3", 3, first_digest, trace="trace-gap"))
        ledger2 = InteractionLedger(policy())
        parent = ledger2.append(segment("tamper-1", 1, trace="trace-tamper"))
        with self.assertRaises(InteractionLedgerError):
            ledger2.append(segment("tamper-2", 2, digest({"wrong": 1}), trace="trace-tamper"))
        self.assertTrue(parent.startswith("sha256:"))

    def test_binding_and_terminal_requirements(self):
        ledger = InteractionLedger(policy())
        first = segment("bind-1", 1, trace="trace-bind")
        second = segment("bind-2", 2, ledger.append(first), trace="trace-bind")
        ledger.append(second)
        with self.assertRaises(InteractionLedgerError):
            ledger.admit(LedgerRequest("wrong", "trace-bind", "other-task", "artifact-1", CAP, DELEGATION, ROUTE, "audience-tools", 7, policy().policy_digest, "bind-2", 1, 2, (first.segment_digest, second.segment_digest), terminal("bind-2", "term-bind"), 20, 80, "nonce-wrong"), now=31, authority=AUTHORITY)
        with self.assertRaises(InteractionLedgerError):
            ledger.admit(request(ledger, [first, second], "no-terminal", with_terminal=False), now=31, authority=AUTHORITY)
        with self.assertRaises(InteractionLedgerError):
            ledger.admit(LedgerRequest("unverified", "trace-bind", "task-1", "artifact-1", CAP, DELEGATION, ROUTE, "audience-tools", 7, policy().policy_digest, "bind-2", 1, 2, (first.segment_digest, second.segment_digest), terminal("bind-2", "term-unverified", False), 20, 80, "nonce-unverified"), now=31, authority=AUTHORITY)

    def test_replay_tamper_expiry_and_policy_generation(self):
        ledger = InteractionLedger(policy())
        first = segment("replay-1", 1, trace="trace-replay")
        second = segment("replay-2", 2, ledger.append(first), trace="trace-replay")
        ledger.append(second)
        req = LedgerRequest("replay", "trace-replay", "task-1", "artifact-1", CAP, DELEGATION, ROUTE, "audience-tools", 7, policy().policy_digest, "replay-2", 1, 2, (first.segment_digest, second.segment_digest), terminal("replay-2", "term-replay"), 20, 80, "nonce-replay")
        ledger.admit(req, now=31, authority=AUTHORITY)
        with self.assertRaises(InteractionLedgerError):
            ledger.admit(req, now=32, authority=AUTHORITY)
        with self.assertRaises(InteractionLedgerError):
            ledger.admit(LedgerRequest("expired", "trace-replay", "task-1", "artifact-1", CAP, DELEGATION, ROUTE, "audience-tools", 7, policy().policy_digest, "replay-2", 1, 2, (first.segment_digest, second.segment_digest), terminal("replay-2", "term-expired"), 20, 32, "nonce-expired"), now=32, authority=AUTHORITY)
        with self.assertRaises(InteractionLedgerError):
            ledger.admit(LedgerRequest("authority", "trace-replay", "task-1", "artifact-1", CAP, DELEGATION, ROUTE, "audience-tools", 7, policy().policy_digest, "replay-2", 1, 2, (first.segment_digest, second.segment_digest), terminal("replay-2", "term-authority"), 20, 80, "nonce-authority"), now=31, authority=dict(AUTHORITY, telemetry_is_kernel_ground_truth=True))

    def test_trace_start_and_digest_tamper(self):
        ledger = InteractionLedger(policy())
        with self.assertRaises(InteractionLedgerError):
            ledger.append(segment("bad-start", 2))
        good = InteractionLedger(policy())
        first = segment("good-1", 1)
        good.append(first)
        second = segment("good-2", 2, first.segment_digest)
        good.append(second)
        with self.assertRaises(InteractionLedgerError):
            good.admit(LedgerRequest("tamper", "trace-1", "task-1", "artifact-1", CAP, DELEGATION, ROUTE, "audience-tools", 7, policy().policy_digest, "good-2", 1, 2, (digest({"wrong": 1}), second.segment_digest), terminal("good-2", "term-tamper"), 20, 80, "nonce-tamper"), now=31, authority=AUTHORITY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
