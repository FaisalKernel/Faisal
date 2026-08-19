#!/usr/bin/env bash
set -euo pipefail

OUT=${1:?output directory required}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-eval-thread${PYTHONPATH:+:$PYTHONPATH}"
python3 -m py_compile "$ROOT"/tools/faisal-eval-thread/*.py
python3 "$ROOT/tools/faisal-eval-thread/test_faisal_thread_eval.py" | tee "$OUT/unit-tests.log"
python3 "$ROOT/tools/faisal-eval-thread/bench_faisal_thread_eval.py" | tee "$OUT/benchmark.log"
ROOT="$ROOT" OUT="$OUT" python3 - <<'PY'
from __future__ import annotations
import copy
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["ROOT"])
out = Path(os.environ["OUT"])
sys.path.insert(0, str(root / "tools/faisal-eval-thread"))
from faisal_thread_eval import ExpectedThread, ThreadEvalError, ThreadEvaluator, ThreadPolicy, digest

def make_turn(number: int, state: str, outcome: str, status: str = "complete", safety: bool = True):
    return {
        "turn": number,
        "status": status,
        "input_digest": digest({"input": number}),
        "output_digest": digest({"output": number}),
        "state_digest": digest({"state": state}),
        "outcome_digest": digest({"outcome": outcome}),
        "safety_passed": safety,
        "runs": [{"run_id": f"run-{number}", "tool_name": "observe", "tool_args_digest": digest({"arg": number}), "safety_passed": safety}],
        "latency_ns": 1000 + number,
        "authority": {
            "model_output_is_authority": False,
            "tool_output_is_authority": False,
            "trace_is_execution_authority": False,
            "evaluation_is_production_approval": False,
        },
    }

evaluator = ThreadEvaluator(ThreadPolicy(max_trials=3))
expected = ExpectedThread("runner-thread", digest({"state": "final"}), digest({"outcome": "done"}), 3, True)
good_turns = [make_turn(1, "intermediate", "working"), make_turn(2, "intermediate-2", "working"), make_turn(3, "final", "done")]
good = evaluator.verify_trace(candidate_id="runner-candidate", version="v1", trial_id="trial-good", thread_id="runner-thread", turns=good_turns, expected=expected)
assert good["trace_passed"] is True
bad_turns = [make_turn(1, "intermediate", "working"), make_turn(2, "intermediate-2", "working"), make_turn(3, "wrong", "wrong")]
bad = evaluator.verify_trace(candidate_id="runner-candidate", version="v1", trial_id="trial-bad", thread_id="runner-thread", turns=bad_turns, expected=expected)
assert bad["trace_passed"] is False
aggregate = evaluator.aggregate_trials([good, bad], candidate_id="runner-candidate", version="v1", thread_id="runner-thread")
assert aggregate["pass_at_k"] is True and aggregate["pass_all_k"] is False
negative = {}
try:
    evaluator.aggregate_trials([good, good], candidate_id="runner-candidate", version="v1", thread_id="runner-thread")
except ThreadEvalError as exc:
    negative["duplicate_trial"] = str(exc)
tampered = copy.deepcopy(good)
tampered["authority"]["model_output_is_authority"] = True
try:
    evaluator.aggregate_trials([tampered], candidate_id="runner-candidate", version="v1", thread_id="runner-thread")
except ThreadEvalError as exc:
    negative["authority_tamper"] = str(exc)
unsafe_turns = [make_turn(1, "intermediate", "working"), make_turn(2, "intermediate-2", "working"), make_turn(3, "final", "done", safety=False)]
unsafe = evaluator.verify_trace(candidate_id="runner-candidate", version="v1", trial_id="trial-unsafe", thread_id="runner-thread", turns=unsafe_turns, expected=expected)
assert unsafe["trace_passed"] is False and unsafe["safety_passed"] is False
assert len(negative) == 2
payload = {
    "schema": "FAISAL-THREAD-EVAL-VALIDATION-1",
    "module": "tools/faisal-eval-thread/faisal_thread_eval.py",
    "good_trace_digest": good["trace_digest"],
    "bad_trace_status": bad["status"],
    "unsafe_trace_status": unsafe["status"],
    "aggregate": aggregate,
    "negative_cases": negative,
    "authority_boundaries": {
        "model_output_is_authority": False,
        "tool_output_is_authority": False,
        "trace_is_execution_authority": False,
        "evaluation_is_production_approval": False,
    },
}
payload["record_digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
(out / "thread-eval-validation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print("FAISAL_THREAD_EVAL_VALIDATION_OK")
print("FAISAL_THREAD_EVAL_RECORD", out / "thread-eval-validation.json")
print("FAISAL_THREAD_EVAL_RECORD_DIGEST", payload["record_digest"])
PY
printf '%s\n' 'FAISAL_THREAD_EVAL_OK tests=6_passed benchmark=passed trace=passed state_change=passed outcome=passed multi_trial=passed pass_at_k=passed pass_all_k=passed replay=passed tamper=passed safety=passed authority=passed' > "$OUT/validation.marker"
