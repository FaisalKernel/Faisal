from __future__ import annotations

import statistics
import time

from faisal_evaluation_set import EvaluationPolicy, EvaluationResult, EvaluationSetLedger, EvaluationSetManifest, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "grader_output_is_authority": False,
    "evaluation_receipt_is_deployment_authority": False,
    "evaluation_receipt_is_policy_authority": False,
    "evaluation_receipt_is_production_authority": False,
    "dataset_manifest_is_truth": False,
}


def build():
    p = EvaluationPolicy("p", "v1", 7, 47, min_task_count=4, min_coverage_per_mille=1000, max_ttl=120)
    m = EvaluationSetManifest("set", digest({"tasks": 1}), digest({"split": 1}), digest({"grader": 1}), p.policy_digest, 4, 1000, 0, 0, True, True, 7, 20, 100)
    r = EvaluationResult("result", m.set_id, m.manifest_digest, digest({"baseline": 1}), digest({"candidate": 1}), digest({"tasks": 1}), digest({"traces": 1}), 4, 4, 0, 30)
    return p, m, r


def measure(fn, count=1000):
    samples = []
    for i in range(count):
        start = time.perf_counter_ns(); fn(i); samples.append(time.perf_counter_ns() - start)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]


def main():
    p, m, r = build()

    def baseline(i):
        return {"manifest": m.manifest_digest, "result": r.result_digest, "tasks": r.completed_tasks}

    def admit(i):
        policy, manifest, result = build(); l = EvaluationSetLedger(policy)
        return l.admit_manifest(manifest, now=31, authority=AUTHORITY)

    def verify(i):
        policy, manifest, result = build(); l = EvaluationSetLedger(policy)
        l.admit_manifest(manifest, now=31, authority=AUTHORITY)
        return l.verify_result(result, now=31, authority=AUTHORITY, nonce=f"nonce-{i}")

    for name, fn in (("baseline_ungoverned", baseline), ("manifest_admit", admit), ("result_verify", verify)):
        mean, p95 = measure(fn)
        print(f"FAISAL_EVALUATION_SET_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
