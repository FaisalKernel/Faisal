from __future__ import annotations
import statistics
import time
from faisal_intent_repair import IntentPolicy, IntentRepairLedger, RepairProposal, SubtaskProposal, digest

AUTH = {"model_output_is_authority": False, "verifier_output_is_authority": False, "artifact_is_authority": False, "intent_receipt_is_execution_authority": False, "intent_receipt_is_production_authority": False, "production_approval": False}
INTENT = digest({"task": "bench"}); C1 = digest({"constraint": "test"}); C2 = digest({"constraint": "scope"}); SUB = digest({"subtask": "bench"}); ART = digest({"artifact": "bench"}); CK = digest({"checkpoint": 1}); VER = digest({"verifier": 1})
POLICY = IntentPolicy("bench", INTENT, tuple(sorted((C1, C2))), 7, 10, 100, 100, 100)

def sub(): return SubtaskProposal("sub", INTENT, SUB, tuple(sorted((C1, C2))), (), CK, 1, 7, 20)
def repair(): return RepairProposal("repair", INTENT, ART, (C1,), VER, CK, 2, 1, 7, 20, False)

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * .95) - 1]

def main():
    def baseline(): digest({"intent": INTENT, "subtask": SUB})
    def subtask(): IntentRepairLedger(POLICY).admit_subtask(sub(), current_generation=7, nonce="s", authority=AUTH, now=21)
    def repair_path(): IntentRepairLedger(POLICY).admit_repair(repair(), current_generation=7, nonce="r", authority=AUTH, now=21)
    for name, fn in (("baseline_ungoverned", baseline), ("subtask_admission", subtask), ("repair_admission", repair_path)):
        mean, p95 = sample(fn)
        print(f"FAISAL_INTENT_REPAIR_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
