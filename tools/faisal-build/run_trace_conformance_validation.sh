#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-"$ROOT/../../build/frontier/trace-conformance-validation"}
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-trace-cert:$ROOT/tools/faisal-trace-conformance${PYTHONPATH:+:$PYTHONPATH}"
python3 "$ROOT/tools/faisal-trace-conformance/test_faisal_trace_conformance.py" | tee "$OUT/selftest.log"
python3 - "$OUT/trace-conformance-validation.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
from faisal_trace_cert import EvidenceRef, ReplayGuard, TraceProposal, TraceStep, certify_trace
from faisal_trace_conformance import RealizedStep, TraceConformanceError, verify_conformance, verify_receipt_chain

out = Path(sys.argv[1])
evidence = {"sha256:obs": EvidenceRef("sha256:obs", "observation", "obs://runner")}
s1 = TraceStep("s1", "read", "read", "example", "read:example", ("sha256:obs",), generation=6)
s2 = TraceStep("s2", "transform", "transform", "local", "transform:local", ("sha256:obs",), depends_on=("s1",), generation=6)
proposal = TraceProposal("conformance-runner", "agent-runner", "policy-11", 6, "conformance-runner-nonce", (s1, s2), 10, frozenset({"read:example", "transform:local"}))
certificate = certify_trace(proposal, evidence, expected_policy_version="policy-11", expected_generation=6, replay_guard=ReplayGuard())
realized = [RealizedStep("s1", "read", "example", "read:example", "completed", "sha256:" + "1" * 64, generation=6), RealizedStep("s2", "transform", "local", "transform:local", "completed", "sha256:" + "2" * 64, generation=6)]
complete = verify_conformance(proposal, certificate, realized, expected_generation=6)
assert complete["conformance"] == "complete" and complete["completion"] is True and verify_receipt_chain(proposal, complete["receipt_chain"])
failed = verify_conformance(proposal, certificate, [realized[0], RealizedStep("s2", "transform", "local", "transform:local", "failed", None, "TOOL_TIMEOUT", 6)], expected_generation=6)
assert failed["conformance"] == "halt_required" and failed["completion"] is False
incomplete = verify_conformance(proposal, certificate, [realized[0]], expected_generation=6)
assert incomplete["conformance"] == "incomplete" and incomplete["completion"] is False
negative = {}
for name, candidate in {
    "extra": realized + [RealizedStep("s3", "x", "x", "x", "completed", "sha256:" + "3" * 64, generation=6)],
    "reordered": list(reversed(realized)),
    "mismatch": [RealizedStep("s1", "write", "example", "read:example", "completed", "sha256:" + "1" * 64, generation=6), realized[1]],
    "stale_generation": [realized[0], RealizedStep("s2", "transform", "local", "transform:local", "completed", "sha256:" + "2" * 64, generation=5)],
}.items():
    try:
        verify_conformance(proposal, certificate, candidate, expected_generation=6)
    except TraceConformanceError as exc:
        negative[name] = str(exc)
assert len(negative) == 4
chain = [dict(item) for item in complete["receipt_chain"]]
chain[1]["step"] = dict(chain[1]["step"])
chain[1]["step"]["result_digest"] = "sha256:" + "f" * 64
assert verify_receipt_chain(proposal, chain) is False
payload = {
    "schema": "FAISAL-TRACE-CONFORMANCE-VALIDATION-1",
    "complete_conformance": complete["conformance"],
    "failed_conformance": failed["conformance"],
    "incomplete_conformance": incomplete["conformance"],
    "receipt_chain_length": len(complete["receipt_chain"]),
    "receipt_chain_verified": verify_receipt_chain(proposal, complete["receipt_chain"]),
    "tampered_chain_rejected": True,
    "negative_cases": negative,
    "authority_boundaries": {"receipt_is_signature": False, "receipt_is_execution": False, "result_correctness": False, "model_output_is_authority": False, "production_approval": False},
    "limitations": ["conformance checks structure and receipt integrity, not external result correctness", "no tool, browser, model, network, or side effect was executed", "production signing and independent attestation are outside this module", "this is not production approval"],
}
out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
print("FAISAL_TRACE_CONFORMANCE_VALIDATION_OK")
print("FAISAL_TRACE_CONFORMANCE_RECORD", out)
print("FAISAL_TRACE_CONFORMANCE_RECORD_DIGEST", "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest())
PY
printf 'FAISAL_TRACE_CONFORMANCE_OK\n' > "$OUT/validation.marker"
