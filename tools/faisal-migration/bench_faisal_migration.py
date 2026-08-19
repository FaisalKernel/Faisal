#!/usr/bin/env python3
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_migration import MigrationLedger, MigrationPolicy, MigrationRequest, ReadinessEvidence, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "source_agent_card_is_authority": False,
    "destination_agent_card_is_authority": False,
    "readiness_evidence_is_hardware_qualification": False,
    "migration_receipt_is_execution_authority": False,
    "state_manifest_is_trust_root": False,
}
POLICY = MigrationPolicy(frozenset({"node-b"}), frozenset({"cpu", "memory"}), frozenset({"network_path_ready", "storage_ready", "sandbox_ready", "observability_ready"}), 300)


def req(i: int, destination: str = "node-b") -> MigrationRequest:
    readiness = ReadinessEvidence(True, True, False, True, True, digest({"readiness": i}))
    return MigrationRequest(
        f"m-{i}", "node-a", destination, "objective-bench", f"task-{i}", 4,
        digest({"lifecycle": i}), digest({"checkpoint": i}), digest({"trace": i}), digest({"state": i}), digest({"artifact": i}), 7,
        frozenset({"cpu", "memory", "network"}), frozenset({"cpu", "memory"}), readiness, f"idem-{i}", digest({"rollback": i}), 100, 300,
    )


def main(iterations: int = 1000) -> None:
    prepare = []
    commit = []
    deny = []
    for i in range(iterations):
        l = MigrationLedger(generation=4, policy=POLICY)
        r = req(i)
        started = time.perf_counter_ns(); l.prepare(r, now=110, authority_boundary=AUTHORITY); prepare.append(time.perf_counter_ns() - started)
        started = time.perf_counter_ns(); l.commit(r.migration_id, destination_state_digest=digest({"state": i}), destination_checkpoint_digest=digest({"checkpoint": i}), destination_trace_digest=digest({"trace": i}), now=120, authority_boundary=AUTHORITY); commit.append(time.perf_counter_ns() - started)
        bad = req(i + iterations, destination="node-z")
        started = time.perf_counter_ns()
        try:
            l.prepare(bad, now=110, authority_boundary=AUTHORITY)
        except ValueError:
            pass
        deny.append(time.perf_counter_ns() - started)
    for name, values in (("PREPARE", prepare), ("COMMIT", commit), ("DENY", deny)):
        print(f"FAISAL_MIGRATION_{name}_MEAN_NS={statistics.mean(values):.2f}")
        print(f"FAISAL_MIGRATION_{name}_P95_NS={sorted(values)[int(iterations * 0.95) - 1]}")
    print(f"FAISAL_MIGRATION_BENCHMARK_ITERATIONS={iterations}")
    print("FAISAL_MIGRATION_BENCHMARK_OK")
    print("FAISAL_MIGRATION_BENCHMARK_SCOPE=local_python_receipts_not_network_memory_kv_or_device_migration_latency")


if __name__ == "__main__":
    main()
