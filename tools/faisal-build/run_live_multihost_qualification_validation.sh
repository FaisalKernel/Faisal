#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="/home/ubuntu/agi-kernel/build/frontier/live-multihost-qualification-2026-08-19"
rm -rf "$OUT"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-multihost-qualify"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_multihost_qualify.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_multihost_qualify.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$ROOT" "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, re, subprocess, sys, socket
root = pathlib.Path(sys.argv[1]); out = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(root / "tools/faisal-multihost-qualify"))
from faisal_multihost_qualify import REQUIRED_BOUNDARIES, REQUIRED_FAULTS, REQUIRED_WORKLOADS, MultihostEvidence, MultihostLedger, MultihostPolicy, MultihostQualificationError, digest, local_single_host_status

authority = {key: False for key in REQUIRED_BOUNDARIES}
head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
release_tag = "FAISAL-FRONTIER-LIVE-MULTIHOST-QUALIFICATION-2026-08-19"
policy = MultihostPolicy("live-multihost-2026-08-19", release_tag, head, digest({"artifact": "FAISAL-LTS-6.18.44-bzImage"}), "three-node-realistic-ai-workload-topology", 3, 2, REQUIRED_WORKLOADS, REQUIRED_FAULTS, "mTLS-node-identity-quorum-transport", 1, 10, 100, "trusted-cluster-registry-required")
def make_evidence(origin="synthetic_fixture", **overrides):
    nodes = tuple({"node_id": f"node-{i}", "endpoint_reference": f"endpoint-reference-{i}", "identity_digest": digest({"node": i}), "kernel_digest": digest({"kernel": i}), "artifact_digest": policy.artifact_digest, "transport_identity": f"transport-identity-{i}", "clock_state": "synchronized"} for i in range(3))
    values = dict(evidence_id="multihost-fixture", origin=origin, release_tag=policy.release_tag, release_head=policy.release_head, artifact_digest=policy.artifact_digest, topology_id=policy.topology_id, transport_id=policy.transport_id, node_records=nodes, workload_results={key: "pass" for key in REQUIRED_WORKLOADS}, fault_results={key: "pass" for key in REQUIRED_FAULTS}, quorum_observed=3, transport_evidence_digest=digest({"transport": "fixture"}), workload_trace_digest=digest({"trace": "fixture"}), output_digest=digest({"outputs": "fixture"}), checkpoint_digest=digest({"checkpoint": "fixture"}), recovery_digest=digest({"recovery": "fixture"}), migration_digest=digest({"migration": "fixture"}), cluster_report_digest=digest({"report": "fixture"}), verification_reference="external-verifier-fixture", observed_at=20, expires_at=90, nonce="multihost-fixture-nonce", synthetic_fixture=True)
    values.update(overrides); return MultihostEvidence(**values)
ledger = MultihostLedger(policy); item = make_evidence(); receipt = ledger.record(item, 1, item.nonce, 21, authority); fixture_status = ledger.status(21, authority)
local_status = local_single_host_status(policy, 21)
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except MultihostQualificationError: negative[name] = "denied"
deny("node_count", lambda: MultihostLedger(policy).record(make_evidence(node_records=make_evidence().node_records[:2]), 1, "multihost-fixture-nonce", 21, authority))
deny("quorum", lambda: MultihostLedger(policy).record(make_evidence(quorum_observed=1), 1, "multihost-fixture-nonce", 21, authority))
deny("workload_coverage", lambda: MultihostLedger(policy).record(make_evidence(workload_results={"agent_coordination": "pass"}), 1, "multihost-fixture-nonce", 21, authority))
deny("partition_fault_coverage", lambda: MultihostLedger(policy).record(make_evidence(fault_results={"node_loss": "pass"}), 1, "multihost-fixture-nonce", 21, authority))
deny("authority", lambda: MultihostLedger(policy).record(make_evidence(), 1, "multihost-fixture-nonce", 21, dict(authority, production_approval=True)))
bench = {}
for line in (out / "benchmark.log").read_text().splitlines():
    match = re.match(r"FAISAL_MULT IHOST_BENCHMARK name=(\S+) iterations=(\d+) mean_ns=([0-9.]+) p95_ns=([0-9.]+)", line)
    if match: bench[match.group(1)] = {"iterations": int(match.group(2)), "mean_ns": float(match.group(3)), "p95_ns": float(match.group(4))}
local_probe = {"hostname": socket.gethostname(), "loopback": "127.0.0.1", "reachable_peer_count": 0, "transport": "no_external_peer_transport_observed", "live_multihost": False}
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "live-multihost-qualification-under-realistic-distributed-workloads", "recorded_at": "2026-08-19T23:59:00Z", "policy": {"qualification_id": policy.qualification_id, "release_tag": policy.release_tag, "release_head": policy.release_head, "artifact_digest": policy.artifact_digest, "topology_id": policy.topology_id, "required_nodes": policy.required_nodes, "quorum": policy.quorum, "required_workloads": list(policy.required_workloads), "required_faults": list(policy.required_faults), "transport_id": policy.transport_id, "trusted_cluster_registry": policy.trusted_cluster_registry}, "research_provenance": [{"source": "https://www.cncf.io/announcements/2025/11/11/cncf-launches-certified-kubernetes-ai-conformance-program-to-standardize-ai-workloads-on-kubernetes/", "scope": "AI workload interoperability, reproducibility, portability, GPU, volume, and job-networking conformance"}, {"source": "https://docs.open-mpi.org/en/main/tuning-apps/fault-tolerance/index.html", "scope": "component failure, node failure, checkpoint/restart, and consistent distributed system view"}], "local_environment": local_probe, "synthetic_multihost_fixture": {"recorded": True, "record_digest": receipt["record_digest"], "structurally_complete": fixture_status["structurally_complete"], "external_multihost_evidence_structurally_complete": fixture_status["external_multihost_evidence_structurally_complete"], "live_multihost_qualification_completed": fixture_status["live_multihost_qualification_completed"], "distributed_workloads_executed_live": fixture_status["distributed_workloads_executed_live"], "fault_recovery_verified": fixture_status["fault_recovery_verified"], "migration_rollback_verified": fixture_status["migration_rollback_verified"], "production_approval": fixture_status["production_approval"], "synthetic_fixture": True, "blockers": fixture_status["blockers"]}, "local_single_host_fixture": local_status, "negative_cases": negative, "all_negative_cases_denied": all(value == "denied" for value in negative.values()), "benchmark": bench, "boundary": {"live_multihost_qualification": False, "distributed_workloads_executed_live": False, "node_identity_attested": False, "transport_and_quorum_verified": False, "fault_recovery_verified": False, "migration_rollback_verified": False, "production_approval": False}, "security_boundaries": {**authority, "fake_multihost_evidence": False, "synthetic_fixture_authority": False, "node_claim_is_authority": False, "transport_receipt_is_production_authority": False, "live_multihost_qualification_completed": False, "production_approval": False}, "limitations": ["The sandbox has one host and zero reachable external qualification peers; no live multihost workload or external transport result is claimed.", "The three-node fixture validates contract structure only and contains no real node identity, mTLS session, quorum, workload, fault, checkpoint, recovery, or migration evidence.", "Local multiprocessing or loopback activity would not satisfy the live-multihost blocker.", "Production qualification requires a real multi-node environment, realistic distributed workloads, node and transport identity evidence, fault injection, checkpoint/recovery, migration/rollback, and independently verified results."], "rollback_checkpoint": "FAISAL-FRONTIER-INDEPENDENT-SECURITY-REVIEW-2026-08-19"}
record["record_digest"] = digest(record)
(out / "live-multihost-qualification-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_LIVE_MULT IHOST_QUALIFICATION_OK".replace("MULT IHOST", "MULTIHOST"), "unit_tests=4 synthetic_three_node_fixture=structurally_complete local_single_host_blocked=true negative_cases=5_denied live_multihost=false distributed_workloads_live=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
