from __future__ import annotations
import statistics
import time
from faisal_kv_cache_admission import AgentHints, CacheAdmissionRequest, CachePolicy, KVCacheAdmissionLedger, digest

AUTH = {"model_output_is_authority": False, "provider_metadata_is_authority": False, "cache_hint_is_execution_authority": False, "cache_hint_is_policy_authority": False, "production_approval": False}
SURFACE = digest({"surface": "bench"})
ROUTE = digest({"route": "bench"})
POLICY = CachePolicy("bench-policy", 7, 100, 50, 4096, 10000)

def request(i: int) -> CacheAdmissionRequest:
    return CacheAdmissionRequest(f"r-{i}", f"s-{i}", ROUTE, SURFACE, 7, 20, AgentHints(10, 512, True, 60, True), "genesis")

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * .95) - 1]

def main():
    def baseline():
        digest({"priority": 10, "output": 512, "ttl": 60, "speculative_prefill": True})
    def admit():
        ledger = KVCacheAdmissionLedger(POLICY); ledger.admit(request(1), current_generation=7, nonce="n", authority=AUTH, now=21)
    for name, fn in (("baseline_ungoverned", baseline), ("admission", admit)):
        mean, p95 = sample(fn)
        print(f"FAISAL_KV_CACHE_ADMISSION_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
