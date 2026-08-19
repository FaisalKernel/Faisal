from __future__ import annotations
import statistics
import time
from faisal_route_receipt import RouteReceiptLedger, RouteReceiptPolicy, RouteReceiptRequest, TrajectorySummary, digest

AUTH = {"model_output_is_authority": False, "provider_metadata_is_authority": False, "confidence_is_truth": False, "route_receipt_is_execution_authority": False, "route_receipt_is_policy_authority": False, "production_approval": False}
TASK = "bench-task"; SESSION = "bench-session"; INTENT = digest({"task": TASK}); MODELS = ("model-small", "model-large"); VERSIONS = ("v1", "v2"); PROVIDERS = ("provider-a", "provider-b")
POLICY = RouteReceiptPolicy("bench", TASK, SESSION, INTENT, MODELS, VERSIONS, PROVIDERS, 2, 7, 10, 100, 1000, 0.7, 0.6)
REQUEST = RouteReceiptRequest("request", TASK, SESSION, INTENT, "model-small", "v1", "model-large", "v2", "provider-a", "standard", ("model-large",), True, TrajectorySummary(3, 0.82, 0.8, 0.7, 0.75, 0.2, 1), 200, 7, 20)

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * 0.95) - 1]

def main():
    def baseline(): digest({"requested": "model-small", "effective": "model-large", "fallback": ["model-large"], "confidence": 0.8})
    def admit(): RouteReceiptLedger(POLICY).admit(REQUEST, current_generation=7, nonce="n", authority=AUTH, now=21)
    for name, fn in (("baseline_ungoverned", baseline), ("route_receipt_admission", admit)):
        mean, p95 = sample(fn)
        print(f"FAISAL_ROUTE_RECEIPT_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
