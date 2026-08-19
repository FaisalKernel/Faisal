from __future__ import annotations
import statistics
import time
from faisal_handoff_authorization import HandoffAuthorizationLedger, HandoffAuthorizationPolicy, HandoffAuthorizationRequest, digest

AUTH = {"model_output_is_authority": False, "agent_claim_is_authority": False, "memory_is_authority": False, "authorization_receipt_is_execution_authority": False, "authorization_receipt_is_policy_authority": False, "production_approval": False}
TASK = "bench-task"; ORIGINAL = digest({"request": TASK}); SOURCE = digest({"policy": "source"}); M1 = digest({"memory": 1}); M2 = digest({"memory": 2})
POLICY = HandoffAuthorizationPolicy("bench", TASK, ORIGINAL, SOURCE, ("delete", "read", "search", "write"), ("write",), ("delete",), tuple(sorted((M1, M2))), 7, 10, 100, 2)
REQUEST = HandoffAuthorizationRequest("request", "handoff", "agent-a", "agent-b", TASK, ORIGINAL, SOURCE, ("read", "search", "write"), ("read", "search"), (M1,), 7, 20, 90, 1)

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * 0.95) - 1]

def main():
    def baseline(): digest({"parent_scope": ["read", "search", "write"], "requested_scope": ["read", "search"], "memory": [M1]})
    def admit(): HandoffAuthorizationLedger().admit(REQUEST, policy=POLICY, current_generation=7, nonce="n", authority=AUTH, now=21)
    for name, fn in (("baseline_ungoverned", baseline), ("handoff_authorization_admission", admit)):
        mean, p95 = sample(fn)
        print(f"FAISAL_HANDOFF_AUTHORIZATION_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
