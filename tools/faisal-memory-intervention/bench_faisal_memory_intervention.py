from __future__ import annotations
import statistics
import time
from faisal_memory_intervention import MemoryInterventionLedger, MemoryInterventionPolicy, MemoryInterventionRequest, digest

AUTH = {"model_output_is_authority": False, "memory_is_authority": False, "intervention_is_execution_authority": False, "intervention_is_policy_authority": False, "production_approval": False}
TASK = "bench-task"; SESSION = "bench-session"; INTENT = digest({"task": TASK}); MEMORY = digest({"memory": "diagnosis"}); E1 = digest({"evidence": 1}); E2 = digest({"evidence": 2})
POLICY = MemoryInterventionPolicy("bench", TASK, SESSION, INTENT, 2, 7, 10, 100, 512, 3, 1000, 0.7, 0.6)
REQUEST = MemoryInterventionRequest("request", TASK, SESSION, INTENT, MEMORY, tuple(sorted((E1, E2))), "failed-attempt-diagnosis", 0.9, 0.8, 128, 1, 10, -1, 7, 20)

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * 0.95) - 1]

def main():
    def baseline(): digest({"memory": MEMORY, "trigger": "failed-attempt-diagnosis", "tokens": 128})
    def admit(): MemoryInterventionLedger(POLICY).admit(REQUEST, current_generation=7, nonce="n", authority=AUTH, now=21)
    for name, fn in (("baseline_ungoverned", baseline), ("intervention_admission", admit)):
        mean, p95 = sample(fn)
        print(f"FAISAL_MEMORY_INTERVENTION_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
