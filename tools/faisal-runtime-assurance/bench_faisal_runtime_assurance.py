from __future__ import annotations
import statistics
import time
from faisal_runtime_assurance import AssuranceEnvelope, RuntimeAssuranceLedger, RuntimeObservation, digest

AUTH = {"model_output_is_authority": False, "observation_is_authority": False, "tool_result_is_authority": False, "assurance_receipt_is_execution_authority": False, "assurance_receipt_is_production_authority": False}
SURFACE = digest({"surface": "bench"})
ENV = AssuranceEnvelope("env-bench", "policy-bench", SURFACE, 7, 10, 86400, 1000, 10, (("cpu", 80),), (("cpu", 100),), frozenset(("continue", "restrict", "quarantine", "terminate")))

def ob(seq, previous, cpu=20, at=20):
    return RuntimeObservation(f"o-{seq}", "w", SURFACE, seq, at, previous, (("cpu", cpu),), digest({"seq": seq, "cpu": cpu}))

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * .95) - 1]

def main():
    def baseline():
        digest({"workload": "w", "cpu": 20})
    def run(cpu, at=20):
        ledger = RuntimeAssuranceLedger(ENV); previous = "genesis"
        for seq in range(1, 2):
            previous = ledger.decide(ob(seq, previous, cpu=cpu, at=at), 21, f"nonce-{cpu}-{at}", AUTH)["decision_digest"]
    for name, fn in (("baseline_ungoverned", baseline), ("continue", lambda: run(20)), ("restrict", lambda: run(90)), ("quarantine", lambda: run(20, 0)), ("terminate", lambda: run(101))):
        mean, p95 = sample(fn)
        print(f"FAISAL_RUNTIME_ASSURANCE_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
