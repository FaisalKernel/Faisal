from __future__ import annotations
import statistics
import time
from faisal_tool_attestation import ToolAttestationLedger, ToolCallRequest, ToolPolicy, digest

AUTH = {"model_output_is_authority": False, "tool_metadata_is_authority": False, "tool_result_is_authority": False, "attestation_is_execution_authority": False, "attestation_is_policy_authority": False, "production_approval": False}
DEFINITION = digest({"tool": "browser.click", "version": 3}); DEPENDENCY = digest({"deps": ["playwright"]})
POLICY = ToolPolicy("bench", "browser", "click", DEFINITION, DEPENDENCY, (1, 4, 0), frozenset(("browser.read",)), 2, 2, 7, 10, 100, False)
REQUEST = ToolCallRequest("request", "browser", "click", DEFINITION, DEPENDENCY, (1, 4, 1), frozenset(("browser.read",)), (("target", 1),), False, 7, 20)

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * .95) - 1]

def main():
    def baseline(): digest({"tool": "click", "args": {"target": 1}})
    def admit(): ToolAttestationLedger(POLICY).admit(REQUEST, current_generation=7, nonce="n", authority=AUTH, now=21)
    for name, fn in (("baseline_ungoverned", baseline), ("attestation_admission", admit)):
        mean, p95 = sample(fn)
        print(f"FAISAL_TOOL_ATTESTATION_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
