#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-"$ROOT/../../build/frontier/trace-cert-validation"}
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-trace-cert${PYTHONPATH:+:$PYTHONPATH}"
python3 "$ROOT/tools/faisal-trace-cert/test_faisal_trace_cert.py" | tee "$OUT/selftest.log"
python3 - "$OUT/trace-cert-validation.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
from faisal_trace_cert import EvidenceRef, ReplayGuard, TraceCertificationError, TraceProposal, TraceStep, certify_trace, verify_certificate

out = Path(sys.argv[1])
evidence = {"sha256:obs": EvidenceRef("sha256:obs", "observation", "obs://runner"), "sha256:approval": EvidenceRef("sha256:approval", "approval", "approval://runner")}
step = TraceStep("s1", "read", "read", "example", "read:example", ("sha256:obs",), cost_units=2, generation=5)
proposal = TraceProposal("runner-trace", "agent-runner", "policy-9", 5, "runner-nonce", (step,), 10, frozenset({"read:example"}))
cert = certify_trace(proposal, evidence, expected_policy_version="policy-9", expected_generation=5, replay_guard=ReplayGuard())
assert verify_certificate(cert, proposal)
negative = {}
for name, fn in {
    "stale_policy": lambda: certify_trace(proposal, evidence, expected_policy_version="policy-8", expected_generation=5, replay_guard=ReplayGuard()),
    "stale_generation": lambda: certify_trace(proposal, evidence, expected_policy_version="policy-9", expected_generation=4, replay_guard=ReplayGuard()),
    "replay": lambda: (lambda guard: (certify_trace(proposal, evidence, expected_policy_version="policy-9", expected_generation=5, replay_guard=guard), certify_trace(proposal, evidence, expected_policy_version="policy-9", expected_generation=5, replay_guard=guard)))(ReplayGuard()),
    "unknown_evidence": lambda: certify_trace(TraceProposal("unknown", "agent-runner", "policy-9", 5, "unknown-nonce", (TraceStep("s1", "read", "read", "example", "read:example", ("sha256:no",), generation=5),), 10, frozenset({"read:example"})), evidence, expected_policy_version="policy-9", expected_generation=5, replay_guard=ReplayGuard()),
}.items():
    try:
        fn()
    except TraceCertificationError as exc:
        negative[name] = str(exc)
assert len(negative) == 4
high = TraceStep("s-high", "submit", "submit", "example", "execute:submit", ("sha256:obs",), cost_units=1, risk="high", side_effect=True, generation=5)
try:
    certify_trace(TraceProposal("high", "agent-runner", "policy-9", 5, "high-nonce", (high,), 10, frozenset({"execute:submit"})), evidence, expected_policy_version="policy-9", expected_generation=5, replay_guard=ReplayGuard())
except TraceCertificationError as exc:
    negative["high_risk_without_approval"] = str(exc)
assert len(negative) == 5
payload = {
    "schema": "FAISAL-TRACE-CERT-VALIDATION-1",
    "certificate_digest": cert["certificate_digest"],
    "proposal_digest": cert["proposal_digest"],
    "certified": cert["certified"],
    "execution_authorized": cert["execution_authorized"],
    "executed": cert["executed"],
    "negative_cases": negative,
    "authority_boundaries": {"model_output_is_authority": False, "evidence_is_authority": False, "certificate_is_execution": False, "production_approval": False},
    "limitations": ["certification is bounded deterministic policy checking, not formal proof of all world properties", "no model, tool, browser, network, or side effect was executed", "caller-supplied policy and evidence registry are trusted inputs but remain non-authoritative content", "this is not production approval"],
}
out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
print("FAISAL_TRACE_CERT_VALIDATION_OK")
print("FAISAL_TRACE_CERT_RECORD", out)
print("FAISAL_TRACE_CERT_RECORD_DIGEST", "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest())
PY
printf 'FAISAL_TRACE_CERT_OK\n' > "$OUT/validation.marker"
