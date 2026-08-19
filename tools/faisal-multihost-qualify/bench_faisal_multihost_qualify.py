#!/usr/bin/env python3
from __future__ import annotations

import statistics
import time
from faisal_multihost_qualify import REQUIRED_BOUNDARIES, REQUIRED_FAULTS, REQUIRED_WORKLOADS, MultihostEvidence, MultihostLedger, MultihostPolicy, digest

ITERATIONS = 1000
AUTH = {key: False for key in REQUIRED_BOUNDARIES}
POLICY = MultihostPolicy("multi-bench", "FAISAL-MULTIHOST-BENCH", "a" * 40, digest({"artifact": "fixture"}), "topology-bench", 3, 2, REQUIRED_WORKLOADS, REQUIRED_FAULTS, "transport-bench", 1, 10, 100, "registry-bench")

def evidence():
    nodes = tuple({"node_id": f"node-{i}", "endpoint_reference": f"endpoint-{i}", "identity_digest": digest({"node": i}), "kernel_digest": digest({"kernel": i}), "artifact_digest": POLICY.artifact_digest, "transport_identity": f"transport-{i}", "clock_state": "synchronized"} for i in range(3))
    return MultihostEvidence("multi-bench", "synthetic_fixture", POLICY.release_tag, POLICY.release_head, POLICY.artifact_digest, POLICY.topology_id, POLICY.transport_id, nodes, {key: "pass" for key in REQUIRED_WORKLOADS}, {key: "pass" for key in REQUIRED_FAULTS}, 3, digest({"transport": 1}), digest({"trace": 1}), digest({"output": 1}), digest({"checkpoint": 1}), digest({"recovery": 1}), digest({"migration": 1}), digest({"report": 1}), "verifier", 20, 90, "nonce-bench", True)

def baseline(): return digest({"release": POLICY.release_tag, "head": POLICY.release_head, "topology": POLICY.topology_id})
def admission():
    ledger = MultihostLedger(POLICY); item = evidence(); ledger.record(item, 1, item.nonce, 21, AUTH)
def status():
    ledger = MultihostLedger(POLICY); item = evidence(); ledger.record(item, 1, item.nonce, 21, AUTH); ledger.status(21, AUTH)
def sample(fn):
    values=[]
    for _ in range(ITERATIONS):
        start=time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns()-start)
    values.sort(); return statistics.mean(values), values[int(ITERATIONS*.95)-1]
for name, fn in (("baseline_manifest_digest", baseline), ("three_node_evidence_admission", admission), ("three_node_status_evaluation", status)):
    mean,p95=sample(fn); print(f"FAISAL_MULT IHOST_BENCHMARK name={name} iterations={ITERATIONS} mean_ns={mean:.2f} p95_ns={p95:.2f}".replace("MULT IHOST", "MULTIHOST"))
print("FAISAL_MULT IHOST_BENCHMARK_SCOPE=local_structural_contract_without_live_nodes_or_external_transport".replace("MULT IHOST", "MULTIHOST"))
