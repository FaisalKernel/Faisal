from __future__ import annotations

import statistics
import time

from faisal_memory_promotion import MemoryPromotionCandidate, MemoryPromotionLedger, PromotionPolicy, PromotionRequest, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "retrieved_content_is_authority": False,
    "memory_content_is_authority": False,
    "promotion_receipt_is_execution_authority": False,
    "promotion_receipt_is_policy_authority": False,
    "promotion_receipt_is_production_authority": False,
}


def candidate(i: int) -> MemoryPromotionCandidate:
    return MemoryPromotionCandidate(
        f"c-{i}", digest({"candidate": i}), "semantic", "agent-a", "tenant-a", ("tenant-a", "project-a"),
        digest({"lineage": i}), 3, 7, 10, 100, 3, digest({"finality": i}), "none",
    )


def request(i: int, c: MemoryPromotionCandidate) -> PromotionRequest:
    return PromotionRequest(f"p-{i}", c.candidate_id, c.candidate_digest, "agent-a", "tenant-a", ("tenant-a", "project-a"), 7, 20, 90, f"nonce-{i}")


def measure(fn, count=1000):
    values = []
    for i in range(count):
        start = time.perf_counter_ns()
        fn(i)
        values.append(time.perf_counter_ns() - start)
    return statistics.mean(values), statistics.quantiles(values, n=20)[18]


def main():
    def baseline(i):
        return candidate(i)

    def promote(i):
        l = MemoryPromotionLedger(PromotionPolicy("p", "v1", 7, frozenset({"semantic"}), ("tenant-a", "project-a")))
        c = candidate(i)
        l.register_candidate(c)
        return l.promote(request(i, c), now=21, authority=AUTHORITY)

    def finality_conflict(i):
        l = MemoryPromotionLedger(PromotionPolicy("p", "v1", 7, frozenset({"semantic"}), ("tenant-a", "project-a"), minimum_finality=3))
        c = candidate(i)
        l.register_candidate(c)
        return l.promote(request(i, c), now=21, authority=AUTHORITY)

    for name, fn in (("baseline_ungoverned", baseline), ("promotion_admit", promote), ("finality_conflict_admit", finality_conflict)):
        mean, p95 = measure(fn)
        print(f"FAISAL_MEMORY_PROMOTION_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
