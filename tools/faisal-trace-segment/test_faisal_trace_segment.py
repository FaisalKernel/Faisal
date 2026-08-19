#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_trace_segment import SegmentCheckpointRequest, Span, TraceSegment, TraceSegmentError, TraceSegmentLedger, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_output_is_authority": False,
    "trace_is_authority": False,
    "checkpoint_is_production_authority": False,
}
POLICY = digest({"sensitive": "redact-v1"})


def span(span_id: str, start: int = 100, end: int = 101) -> Span:
    return Span(span_id, None, "tool", start, end, digest({"span": span_id}), False)


def segment(segment_id: str, sequence_start: int, sequence_end: int, previous: str | None = None, flush: str = "flushed", cancellation: str = "none", generation: int = 4) -> TraceSegment:
    return TraceSegment("trace-1", segment_id, generation, sequence_start, sequence_end, (span(f"{segment_id}-span"),), previous, flush, cancellation, POLICY)


def request(checkpoint_id: str, seg: TraceSegment, required_flush: bool = True, generation: int = 4) -> SegmentCheckpointRequest:
    return SegmentCheckpointRequest(checkpoint_id, "objective-1", seg.trace_id, generation, seg.segment_digest, digest({"lifecycle": checkpoint_id}), digest({"state": checkpoint_id}), required_flush, f"resume-{checkpoint_id}", 120)


class TraceSegmentTests(unittest.TestCase):
    def test_valid_segment_checkpoint_is_admitted(self) -> None:
        seg = segment("seg-1", 0, 0)
        result = TraceSegmentLedger(generation=4, sensitive_data_policy_digest=POLICY).admit(seg, request("cp-1", seg), authority_boundary=AUTHORITY)
        self.assertTrue(result["admitted"])
        self.assertFalse(result["authority"]["trace_is_authority"])

    def test_flush_and_cancellation_boundaries_fail_closed(self) -> None:
        ledger = TraceSegmentLedger(generation=4, sensitive_data_policy_digest=POLICY)
        unflushed = segment("unflushed", 0, 0, flush="not_flushed")
        with self.assertRaises(TraceSegmentError):
            ledger.admit(unflushed, request("cp-unflushed", unflushed), authority_boundary=AUTHORITY)
        cancelled = segment("cancelled", 0, 0, cancellation="requested")
        with self.assertRaises(TraceSegmentError):
            ledger.admit(cancelled, request("cp-cancelled", cancelled, required_flush=False), authority_boundary=AUTHORITY)
        acknowledged = segment("ack", 0, 0, cancellation="acknowledged")
        result = ledger.admit(acknowledged, request("cp-ack", acknowledged), authority_boundary=AUTHORITY)
        self.assertTrue(result["admitted"])

    def test_segment_continuity_and_policy_binding(self) -> None:
        ledger = TraceSegmentLedger(generation=4, sensitive_data_policy_digest=POLICY)
        first = segment("seg-1", 0, 0)
        ledger.admit(first, request("cp-1", first), authority_boundary=AUTHORITY)
        second = segment("seg-2", 1, 1, previous=first.segment_digest)
        result = ledger.admit(second, request("cp-2", second), authority_boundary=AUTHORITY)
        self.assertEqual(result["sequence_start"], 1)
        gap = segment("gap", 3, 3, previous=second.segment_digest)
        with self.assertRaises(TraceSegmentError):
            ledger.admit(gap, request("cp-gap", gap), authority_boundary=AUTHORITY)
        wrong_policy = TraceSegment("wrong", "wrong-seg", 4, 0, 0, (span("wrong-span"),), None, "flushed", "none", digest({"sensitive": "other"}))
        with self.assertRaises(TraceSegmentError):
            TraceSegmentLedger(generation=4, sensitive_data_policy_digest=POLICY).admit(wrong_policy, request("cp-wrong", wrong_policy), authority_boundary=AUTHORITY)

    def test_generation_linkage_and_replay_fences(self) -> None:
        ledger = TraceSegmentLedger(generation=4, sensitive_data_policy_digest=POLICY)
        seg = segment("seg-1", 0, 0)
        ledger.admit(seg, request("cp-1", seg), authority_boundary=AUTHORITY)
        with self.assertRaises(TraceSegmentError):
            ledger.admit(seg, request("cp-1", seg), authority_boundary=AUTHORITY)
        stale = segment("stale", 0, 0, generation=5)
        with self.assertRaises(TraceSegmentError):
            ledger.admit(stale, request("cp-stale", stale, generation=5), authority_boundary=AUTHORITY)
        wrong_trace = copy.copy(request("cp-trace", seg))
        object.__setattr__(wrong_trace, "trace_id", "other-trace")
        with self.assertRaises(TraceSegmentError):
            ledger.admit(seg, wrong_trace, authority_boundary=AUTHORITY)

    def test_tamper_and_span_validation(self) -> None:
        seg = segment("seg-1", 0, 0)
        req = request("cp-1", seg)
        result = TraceSegmentLedger(generation=4, sensitive_data_policy_digest=POLICY).admit(seg, req, authority_boundary=AUTHORITY)
        tampered = copy.deepcopy(result)
        tampered["objective_state_digest"] = digest({"state": "tampered"})
        self.assertNotEqual(tampered["receipt_digest"], digest({k: v for k, v in tampered.items() if k != "receipt_digest"}))
        with self.assertRaises(TraceSegmentError):
            Span("bad", None, "tool", 2, 1, digest({"bad": True}), False)

    def test_authority_boundary_tamper_is_rejected(self) -> None:
        seg = segment("seg-1", 0, 0)
        bad = dict(AUTHORITY, checkpoint_is_production_authority=True)
        with self.assertRaises(TraceSegmentError):
            TraceSegmentLedger(generation=4, sensitive_data_policy_digest=POLICY).admit(seg, request("cp-1", seg), authority_boundary=bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
