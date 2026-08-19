#!/usr/bin/env python3
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_trace_segment import SegmentCheckpointRequest, Span, TraceSegment, TraceSegmentLedger, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_output_is_authority": False,
    "trace_is_authority": False,
    "checkpoint_is_production_authority": False,
}
POLICY = digest({"sensitive": "redact-v1"})


def make_segment(segment_id: str, start: int, previous: str | None = None) -> TraceSegment:
    sp = Span(f"{segment_id}-span", None, "tool", 100, 101, digest({"span": segment_id}), False)
    return TraceSegment("trace-bench", segment_id, 4, start, start, (sp,), previous, "flushed", "none", POLICY)


def make_request(index: int, seg: TraceSegment) -> SegmentCheckpointRequest:
    return SegmentCheckpointRequest(f"cp-{index}", "objective-bench", seg.trace_id, 4, seg.segment_digest, digest({"lifecycle": index}), digest({"state": index}), True, f"resume-{index}", 120)


def main(iterations: int = 1000) -> None:
    admission = []
    continuity = []
    for i in range(iterations):
        seg = make_segment(f"single-{i}", 0)
        ledger = TraceSegmentLedger(generation=4, sensitive_data_policy_digest=POLICY)
        started = time.perf_counter_ns()
        ledger.admit(seg, make_request(i, seg), authority_boundary=AUTHORITY)
        admission.append(time.perf_counter_ns() - started)
        first = make_segment(f"first-{i}", 0)
        second = make_segment(f"second-{i}", 1, first.segment_digest)
        ledger = TraceSegmentLedger(generation=4, sensitive_data_policy_digest=POLICY)
        ledger.admit(first, make_request(i * 2, first), authority_boundary=AUTHORITY)
        started = time.perf_counter_ns()
        ledger.admit(second, make_request(i * 2 + 1, second), authority_boundary=AUTHORITY)
        continuity.append(time.perf_counter_ns() - started)
    print(f"FAISAL_TRACE_SEGMENT_BENCHMARK_ITERATIONS={iterations}")
    print(f"FAISAL_TRACE_SEGMENT_ADMISSION_MEAN_NS={statistics.mean(admission):.2f}")
    print(f"FAISAL_TRACE_SEGMENT_ADMISSION_P95_NS={sorted(admission)[int(iterations * 0.95) - 1]}")
    print(f"FAISAL_TRACE_SEGMENT_CONTINUITY_MEAN_NS={statistics.mean(continuity):.2f}")
    print(f"FAISAL_TRACE_SEGMENT_CONTINUITY_P95_NS={sorted(continuity)[int(iterations * 0.95) - 1]}")
    print("FAISAL_TRACE_SEGMENT_BENCHMARK_OK")
    print("FAISAL_TRACE_SEGMENT_BENCHMARK_SCOPE=local_python_receipts_not_trace_export_or_model_latency")


if __name__ == "__main__":
    main()
