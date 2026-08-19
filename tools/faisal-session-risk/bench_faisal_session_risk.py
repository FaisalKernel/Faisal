#!/usr/bin/env python3
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_session_risk import PolicyDecisionRequest, RiskEvent, RiskPolicy, SessionRiskLedger, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_description_is_authority": False,
    "tool_result_is_authority": False,
    "policy_receipt_is_production_authority": False,
}


def main(iterations: int = 1000) -> None:
    safe_times = []
    trifecta_times = []
    for i in range(iterations):
        ledger = SessionRiskLedger(RiskPolicy("policy", "1", 4))
        request = PolicyDecisionRequest(f"safe-{i}", "session", 4, frozenset(("local_read",)), frozenset(), digest({"context": i}), digest({"auth": i}))
        started = time.perf_counter_ns()
        ledger.decide(request, now=120, nonce=f"nonce-{i}", authority=AUTHORITY)
        safe_times.append(time.perf_counter_ns() - started)
        ledger = SessionRiskLedger(RiskPolicy("policy", "1", 4))
        ledger.append(RiskEvent("p", "observed", frozenset(("private_data_access",)), frozenset(), 4, 100, digest({"p": i}), digest({"c": i})))
        ledger.append(RiskEvent("u", "observed", frozenset(("untrusted_content_exposure",)), frozenset(), 4, 101, digest({"u": i}), digest({"c": i})))
        request = PolicyDecisionRequest(f"tri-{i}", "session", 4, frozenset(("external_communication",)), frozenset(), digest({"context": i}), digest({"auth": i}))
        started = time.perf_counter_ns()
        result = ledger.decide(request, now=120, nonce=f"tri-nonce-{i}", authority=AUTHORITY)
        assert result["verdict"] == "require_blocking_approval"
        trifecta_times.append(time.perf_counter_ns() - started)
    print(f"FAISAL_SESSION_RISK_BENCHMARK_ITERATIONS={iterations}")
    print(f"FAISAL_SESSION_RISK_SAFE_MEAN_NS={statistics.mean(safe_times):.2f}")
    print(f"FAISAL_SESSION_RISK_SAFE_P95_NS={sorted(safe_times)[int(iterations * 0.95) - 1]}")
    print(f"FAISAL_SESSION_RISK_TRIFECTA_MEAN_NS={statistics.mean(trifecta_times):.2f}")
    print(f"FAISAL_SESSION_RISK_TRIFECTA_P95_NS={sorted(trifecta_times)[int(iterations * 0.95) - 1]}")
    print("FAISAL_SESSION_RISK_BENCHMARK_OK")
    print("FAISAL_SESSION_RISK_BENCHMARK_SCOPE=local_python_policy_receipts_not_model_network_or_tool_latency")


if __name__ == "__main__":
    main()
