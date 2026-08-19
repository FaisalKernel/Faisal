from __future__ import annotations

import statistics
import time

from faisal_artifact_lineage import ArtifactLineageLedger, ArtifactSnapshot, LineagePolicy, RefinementRequest, TaskSnapshot, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "artifact_content_is_authority": False,
    "agent_output_is_authority": False,
    "acceptance_evidence_is_execution_authority": False,
    "lineage_receipt_is_policy_authority": False,
    "lineage_receipt_is_production_authority": False,
}


def make_task():
    return TaskSnapshot("task-parent", "context-a", "tenant-a", "completed", 7, digest({"task": 1}), 10, 100)


def make_artifact():
    return ArtifactSnapshot("artifact-v1", "report.json", "task-parent", "context-a", "tenant-a", digest({"artifact": 1}), None, 1, 1, "accepted", 7, 10, 100, ("tenant-a", "project-a"))


def make_request(i: int, artifact: ArtifactSnapshot):
    return RefinementRequest(f"refine-{i}", "task-parent", artifact.artifact_id, artifact.artifact_digest, f"task-child-{i}", "context-a", f"artifact-v2-{i}", digest({"child": i}), "report.json", 2, ("tenant-a", "project-a"), 7, 20, 90, digest({"accept": i}), f"nonce-{i}")


def measure(fn, count=1000):
    samples = []
    for i in range(count):
        start = time.perf_counter_ns()
        fn(i)
        samples.append(time.perf_counter_ns() - start)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]


def main():
    def baseline(i):
        return make_request(i, make_artifact())

    def admit(i):
        l = ArtifactLineageLedger(LineagePolicy("p", "v1", 7, ("tenant-a", "project-a")))
        l.register_task(make_task())
        a = make_artifact()
        l.register_artifact(a)
        return l.admit_refinement(make_request(i, a), now=21, authority=AUTHORITY)

    for name, fn in (("baseline_ungoverned", baseline), ("lineage_refinement_admit", admit)):
        mean, p95 = measure(fn)
        print(f"FAISAL_ARTIFACT_LINEAGE_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
