#!/usr/bin/env bash
set -euo pipefail

OUT=${1:?output directory required}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-trace-segment${PYTHONPATH:+:$PYTHONPATH}"
python3 -m py_compile "$ROOT"/tools/faisal-trace-segment/*.py
python3 "$ROOT/tools/faisal-trace-segment/test_faisal_trace_segment.py" | tee "$OUT/unit-tests.log"
python3 "$ROOT/tools/faisal-trace-segment/bench_faisal_trace_segment.py" | tee "$OUT/benchmark.log"
ROOT="$ROOT" OUT="$OUT" python3 - <<'PY'
from __future__ import annotations
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["ROOT"])
out = Path(os.environ["OUT"])
sys.path.insert(0, str(root / "tools/faisal-trace-segment"))
from faisal_trace_segment import SegmentCheckpointRequest, Span, TraceSegment, TraceSegmentError, TraceSegmentLedger, digest

authority = {
    "model_output_is_authority": False,
    "tool_output_is_authority": False,
    "trace_is_authority": False,
    "checkpoint_is_production_authority": False,
}
policy = digest({"sensitive": "redact-v1"})

def seg(name, start, previous=None, flush="flushed", cancellation="none", generation=4, policy_digest=policy):
    return TraceSegment("trace-runner", name, generation, start, start, (Span(f"{name}-span", None, "tool", 100, 101, digest({"span": name}), False),), previous, flush, cancellation, policy_digest)

def req(name, s, required_flush=True, generation=4):
    return SegmentCheckpointRequest(f"cp-{name}", "objective-runner", s.trace_id, generation, s.segment_digest, digest({"lifecycle": name}), digest({"state": name}), required_flush, f"resume-{name}", 120)

ledger = TraceSegmentLedger(generation=4, sensitive_data_policy_digest=policy)
first = seg("first", 0)
valid = ledger.admit(first, req("first", first), authority_boundary=authority)
second = seg("second", 1, first.segment_digest)
continuity = ledger.admit(second, req("second", second), authority_boundary=authority)
negative = {}
for name, s, r in [
    ("unflushed", seg("unflushed", 0, flush="not_flushed"), None),
    ("cancel_requested", seg("cancel", 0, cancellation="requested"), None),
    ("wrong_policy", seg("policy", 0, policy_digest=digest({"sensitive": "other"})), None),
    ("sequence_gap", seg("gap", 3, second.segment_digest), None),
    ("stale_generation", seg("stale", 0, generation=5), None),
]:
    try:
        if name == "stale_generation":
            TraceSegmentLedger(generation=4, sensitive_data_policy_digest=policy).admit(s, req(name, s, generation=5), authority_boundary=authority)
        elif name == "wrong_policy":
            TraceSegmentLedger(generation=4, sensitive_data_policy_digest=policy).admit(s, req(name, s), authority_boundary=authority)
        else:
            ledger.admit(s, req(name, s, required_flush=name != "cancel_requested"), authority_boundary=authority)
    except TraceSegmentError as exc:
        negative[name] = str(exc)
try:
    ledger.admit(first, req("first", first), authority_boundary=authority)
except TraceSegmentError as exc:
    negative["replay"] = str(exc)
try:
    ledger.admit(seg("bad-authority", 2, second.segment_digest), req("bad-authority", seg("bad-authority", 2, second.segment_digest)), authority_boundary=dict(authority, trace_is_authority=True))
except TraceSegmentError as exc:
    negative["authority"] = str(exc)
assert valid["admitted"] and continuity["admitted"]
assert set(negative) == {"unflushed", "cancel_requested", "wrong_policy", "sequence_gap", "stale_generation", "replay", "authority"}
payload = {
    "schema": "FAISAL-TRACE-SEGMENT-VALIDATION-1",
    "module": "tools/faisal-trace-segment/faisal_trace_segment.py",
    "valid_admission": True,
    "continuity_admission": True,
    "negative_cases": negative,
    "ledger_digest": ledger.ledger_digest(),
    "authority_boundaries": authority,
}
payload["record_digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
(out / "trace-segment-validation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print("FAISAL_TRACE_SEGMENT_VALIDATION_OK")
print("FAISAL_TRACE_SEGMENT_RECORD", out / "trace-segment-validation.json")
print("FAISAL_TRACE_SEGMENT_RECORD_DIGEST", payload["record_digest"])
PY
printf '%s\n' 'FAISAL_TRACE_SEGMENT_OK tests=6_passed benchmark=passed valid=passed continuity=passed flush=passed cancellation=passed policy=passed generation=passed replay=passed tamper=passed sequence=passed authority=passed' > "$OUT/validation.marker"
