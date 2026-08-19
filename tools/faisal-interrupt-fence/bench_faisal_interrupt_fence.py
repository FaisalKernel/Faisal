from __future__ import annotations
import statistics
import time
from faisal_interrupt_fence import InterruptFenceLedger, InterruptFencePolicy, InterruptRequest, digest

AUTH = {"model_output_is_authority": False, "interrupt_is_execution_authority": False, "rollback_is_execution_authority": False, "revocation_is_credential_authority": False, "side_effect_ledger_is_truth": False, "production_approval": False}
TASK = "bench-task"; INTENT = digest({"intent": "original"}); CP = digest({"checkpoint": 1}); ROOT1 = digest({"effects": 1}); ROOT2 = digest({"effects": 2})
POLICY = InterruptFencePolicy("bench", TASK, INTENT, 7, 10, 100, max_checkpoint_age=100, max_trace_lag=100)
PAUSE = InterruptRequest("pause", "pause", TASK, INTENT, INTENT, 7, CP, 1, 2, ROOT1, ROOT1, 1, 1, 1, 20, 90)

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * 0.95) - 1]

def main():
    def baseline(): digest({"operation": "pause", "intent": INTENT, "checkpoint": CP, "trace": 2, "irreversible": 1})
    def admit(): InterruptFenceLedger(POLICY).admit(PAUSE, current_generation=7, nonce="n", authority=AUTH, now=21)
    for name, fn in (("baseline_ungoverned", baseline), ("pause_admission", admit)):
        mean, p95 = sample(fn)
        print(f"FAISAL_INTERRUPT_FENCE_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
