#!/usr/bin/env bash
set -euo pipefail

OUT=${1:?output directory required}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-context-window${PYTHONPATH:+:$PYTHONPATH}"
python3 -m py_compile "$ROOT"/tools/faisal-context-window/*.py
python3 "$ROOT/tools/faisal-context-window/test_faisal_context_window.py" | tee "$OUT/unit-tests.log"
python3 "$ROOT/tools/faisal-context-window/bench_faisal_context_window.py" | tee "$OUT/benchmark.log"
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
sys.path.insert(0, str(root / "tools/faisal-context-window"))
from faisal_context_window import COMPACTION_SCHEMA, ContextError, ContextItem, ContextLedger, ContextPolicy, digest, plan_context, verify_plan

def item(name, tokens, priority, recency, *, trust=2, generation=3, required=False, pinned=False, quarantined=False, expires_at=0):
    return ContextItem(name, "memory", digest({"source": name}), generation, trust, tokens, priority, recency, expires_at, pinned, required, quarantined)

def compaction(omitted, generation, tokens=5):
    return {
        "schema": COMPACTION_SCHEMA,
        "generation": generation,
        "source_item_digests": [x.item_digest for x in omitted],
        "summary_digest": digest({"summary": [x.item_id for x in omitted]}),
        "summary_tokens": tokens,
        "authority": {
            "model_output_is_authority": False,
            "compaction_is_authority": False,
            "context_is_execution_authority": False,
            "production_approval": False,
        },
    }

items = [item("pinned", 20, 2, 1, pinned=True), item("high", 30, 10, 3), item("low", 30, 1, 2), item("untrusted", 1, 100, 9, trust=0), item("quarantine", 1, 100, 9, quarantined=True), item("expired", 1, 100, 9, expires_at=100)]
result = plan_context(items, ContextPolicy(50, minimum_trust_rank=1), generation=3, observed_at=100)
assert result["selected_item_ids"] == ["pinned", "high"]
assert result["rejections"]["untrusted"] == "trust_below_minimum"
assert verify_plan(result, expected_generation=3)["verified"] is True
selected = item("selected", 40, 10, 3)
omitted = item("omitted", 40, 1, 2)
compacted = plan_context([selected, omitted], ContextPolicy(50, allow_partial_context=False), generation=3, observed_at=1, compaction_receipt=compaction([omitted], 3))
assert compacted["compaction"]["summary_tokens"] == 5
ledger = ContextLedger()
admitted = ledger.admit(result, current_generation=3, nonce="admit-1")
assert admitted["admitted"] is True
negative = {}
try:
    ledger.admit(result, current_generation=3, nonce="admit-2")
except ContextError as exc:
    negative["replay"] = str(exc)
tampered = copy.deepcopy(result)
tampered["selected_item_ids"] = []
try:
    verify_plan(tampered, expected_generation=3)
except ContextError as exc:
    negative["tamper"] = str(exc)
required = item("required", 1, 1, 1, trust=0, required=True)
try:
    plan_context([required], ContextPolicy(10), generation=3, observed_at=1)
except ContextError as exc:
    negative["required_rejection"] = str(exc)
wrong_compaction = compaction([omitted], 4)
try:
    plan_context([selected, omitted], ContextPolicy(50, allow_partial_context=False), generation=3, observed_at=1, compaction_receipt=wrong_compaction)
except ContextError as exc:
    negative["compaction_generation"] = str(exc)
assert len(negative) == 4
payload = {
    "schema": "FAISAL-CONTEXT-WINDOW-VALIDATION-1",
    "module": "tools/faisal-context-window/faisal_context_window.py",
    "selected_item_ids": result["selected_item_ids"],
    "omitted_item_ids": result["omitted_item_ids"],
    "compaction_summary_tokens": compacted["compaction"]["summary_tokens"],
    "ledger_digest": ledger.digest(),
    "negative_cases": negative,
    "authority_boundaries": {
        "model_output_is_authority": False,
        "compaction_is_authority": False,
        "context_is_execution_authority": False,
        "production_approval": False,
    },
}
payload["record_digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
(out / "context-window-validation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print("FAISAL_CONTEXT_WINDOW_VALIDATION_OK")
print("FAISAL_CONTEXT_WINDOW_RECORD", out / "context-window-validation.json")
print("FAISAL_CONTEXT_WINDOW_RECORD_DIGEST", payload["record_digest"])
PY
printf '%s\n' 'FAISAL_CONTEXT_WINDOW_OK tests=6_passed benchmark=passed selection=passed trust_filter=passed compaction=passed generation=passed replay=passed tamper=passed required=passed authority=passed' > "$OUT/validation.marker"
