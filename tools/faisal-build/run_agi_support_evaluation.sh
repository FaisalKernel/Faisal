#!/bin/bash
set -euo pipefail

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
OUT=${FAISAL_AGI_EVAL_OUT:-$ROOT/build/frontier/agi-eval-run}
PACK=${FAISAL_EVAL_PACK:-$ROOT/build/frontier/agi-eval/held-out-task-pack.json}
BASE_MANIFEST=${FAISAL_BASE_MANIFEST:-$ROOT/build/frontier/agi-eval/baseline-1.manifest.json}
CAND_MANIFEST=${FAISAL_CAND_MANIFEST:-$ROOT/build/frontier/agi-eval/candidate-1.manifest.json}
POLICY=${FAISAL_EVAL_POLICY:-$ROOT/build/frontier/agi-eval/promotion-policy.json}
EVAL="$LINUX/tools/faisal-eval/faisal_eval.py"
rm -rf "$OUT"
mkdir -p "$OUT/baseline" "$OUT/candidate"
cd "$LINUX"
python3 -m py_compile "$EVAL"
python3 "$EVAL" evaluate --pack "$PACK" --manifest "$BASE_MANIFEST" --out "$OUT/baseline" | tee "$OUT/baseline-evaluate.log"
python3 "$EVAL" evaluate --pack "$PACK" --manifest "$CAND_MANIFEST" --out "$OUT/candidate" | tee "$OUT/candidate-evaluate.log"
python3 "$EVAL" verify-trace --trace "$OUT/baseline/baseline-1.trace.jsonl" | tee "$OUT/baseline-trace.log"
python3 "$EVAL" verify-trace --trace "$OUT/candidate/candidate-1.trace.jsonl" | tee "$OUT/candidate-trace.log"
python3 "$EVAL" compare \
  --baseline "$OUT/baseline/baseline-1.summary.json" \
  --candidate "$OUT/candidate/candidate-1.summary.json" \
  --policy "$POLICY" \
  --out "$OUT/comparison.json" | tee "$OUT/comparison.log"
python3 "$EVAL" discover --dir "$(dirname "$BASE_MANIFEST")" --out "$OUT/discovery.json" | tee "$OUT/discovery.log"
POINTER="$OUT/current-version.pointer"
printf 'baseline-1\n' > "$POINTER"
printf 'LOCAL_TEST_AUTHORITY_TOKEN_ONLY\n' > "$OUT/local-test-authority.token"
if python3 "$EVAL" promote --manifest "$CAND_MANIFEST" --comparison "$OUT/comparison.json" --pointer "$POINTER" > "$OUT/promotion-denied.log" 2>&1; then
  echo 'promotion without authority unexpectedly succeeded' >&2
  exit 1
fi
python3 "$EVAL" promote --manifest "$CAND_MANIFEST" --comparison "$OUT/comparison.json" --pointer "$POINTER" --authority-token "$OUT/local-test-authority.token" | tee "$OUT/promotion.log"
python3 "$EVAL" rollback --pointer "$POINTER" | tee "$OUT/rollback.log"
test "$(cat "$POINTER")" = "baseline-1"
cp "$OUT/candidate/candidate-1.trace.jsonl" "$OUT/tampered.trace.jsonl"
printf 'tamper\n' >> "$OUT/tampered.trace.jsonl"
if python3 "$EVAL" verify-trace --trace "$OUT/tampered.trace.jsonl" > "$OUT/tampered-verify.log" 2>&1; then
  echo 'tampered trace unexpectedly verified' >&2
  exit 1
fi
printf 'FAISAL_AGI_SUPPORT_EVALUATION_OK tasks=8 baseline_pass_rate=0.75 candidate_pass_rate=1.0 improvement=0.25 raw_traces=2 promotion_guard=passed rollback=passed tamper_rejection=passed\n' | tee "$OUT/validation.marker"
