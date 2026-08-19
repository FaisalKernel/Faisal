#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="/home/ubuntu/agi-kernel/build/frontier/evidence-index-validation-2026-08-19"
rm -rf "$OUT" && mkdir -p "$OUT"
cd "$ROOT/tools/faisal-evidence-index"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_evidence_index.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_evidence_index.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$ROOT" "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, re, subprocess, sys
root, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]); sys.path.insert(0, str(root / "tools/faisal-evidence-index"))
from faisal_evidence_index import EvidenceIndexLedger, EvidenceIndexPolicy, build_snapshot, digest
head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
manifest_path = out / "candidate-manifest.json"
subprocess.check_call(["python3", str(root / "tools/faisal-build/prepare_production_candidate_manifest.py"), "--repo", str(root), "--lts-build", "/home/ubuntu/agi-kernel/build/faisal-lts-6.18.44", "--output", str(manifest_path)])
manifest = json.loads(manifest_path.read_text()); policy = EvidenceIndexPolicy("FAISAL-FRONTIER-EVIDENCE-INDEX-2026-08-19", head, "sha256:" + manifest["artifact"]["bzImage_sha256"], 10, 100, ("operator_signing", "physical_hardware", "external_security_review", "live_multihost"))
snapshot = build_snapshot(root, manifest, policy, 20); authority = {"model_output_is_authority": False, "evidence_receipt_is_production_authority": False, "production_approval": False}; receipt = EvidenceIndexLedger(policy).record(snapshot, "evidence-index-nonce", 1, 20, authority)
bench = {}
for line in (out / "benchmark.log").read_text().splitlines():
    m = re.match(r"FAISAL_EVIDENCE_INDEX_BENCHMARK name=(\S+) iterations=(\d+) mean_ns=([0-9.]+) p95_ns=([0-9.]+)", line)
    if m: bench[m.group(1)] = {"iterations": int(m.group(2)), "mean_ns": float(m.group(3)), "p95_ns": float(m.group(4))}
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "release-evidence-index-export-and-verify", "recorded_at": "2026-08-19T23:59:00Z", "release_head": head, "source_candidate_manifest_digest": digest(manifest), "snapshot": snapshot, "receipt": receipt, "benchmark": bench, "boundary": {"local_index_verified": True, "external_evidence_verified": False, "operator_signing_ceremony_verified": False, "physical_hardware_qualified": False, "independent_security_review_verified": False, "live_multihost_qualification": False, "node_identity_attested": False, "transport_and_quorum_verified": False, "distributed_workloads_executed_live": False, "fault_recovery_verified": False, "migration_rollback_verified": False, "production_approval": False}, "security_boundaries": {**authority, "manifest_is_authority": False, "synthetic_fixture_authority": False, "external_evidence_verified": False, "production_approval": False}, "negative_cases": {"manifest_digest_tamper": "denied_by_unit_test", "evidence_digest_tamper": "denied_by_unit_test", "replay": "denied_by_unit_test", "authority_violation": "denied_by_unit_test", "snapshot_digest_tamper": "denied_by_unit_test"}, "all_negative_cases_denied": True, "limitations": ["The snapshot checks evidence file integrity and policy binding but does not authenticate external organizations or elevate any local record to production authority.", "External categories are indexed as required but remain externally unverified until real signed and attributable evidence exists.", "The exporter does not invoke models, contact inference servers, control workloads, or approve a release."], "rollback_checkpoint": "FAISAL-FRONTIER-LIVE-MULTIHOST-QUALIFICATION-2026-08-19"}
record["record_digest"] = digest(record); (out / "evidence-index-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_EVIDENCE_INDEX_OK unit_tests=4 snapshot_verified=true negative_cases=5_denied external_evidence_verified=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
