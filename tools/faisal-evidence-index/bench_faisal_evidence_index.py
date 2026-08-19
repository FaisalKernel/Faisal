#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import statistics
import tempfile
import time

from faisal_evidence_index import EvidenceIndexPolicy, build_snapshot, digest, verify_snapshot

ITERATIONS = 250
with tempfile.TemporaryDirectory() as work:
    root = Path(work); path = root / "tools/faisal-build/evidence/frontier-runtime-assurance-validation.json"; path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"record_digest": "sha256:fixture", "boundary": {"production_approval": False}, "security_boundaries": {"production_approval": False}}))
    artifact = "b" * 64; head = "a" * 40
    manifest = {"repository_head": head, "artifact": {"bzImage_sha256": artifact}, "evidence_index": [{"path": str(path.relative_to(root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}], "release_blockers": ["external"]}
    policy = EvidenceIndexPolicy("FAISAL-BENCH", head, "sha256:" + artifact, 10, 100, ("local_control_plane",))
    def baseline(): return digest(manifest)
    def index(): return build_snapshot(root, manifest, policy, 20)
    def verify(): return verify_snapshot(build_snapshot(root, manifest, policy, 20), policy, 20)
    for name, fn in (("baseline_manifest_digest", baseline), ("evidence_snapshot_build", index), ("evidence_snapshot_verify", verify)):
        values = []
        for _ in range(ITERATIONS):
            start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
        values.sort(); print(f"FAISAL_EVIDENCE_INDEX_BENCHMARK name={name} iterations={ITERATIONS} mean_ns={statistics.mean(values):.2f} p95_ns={values[int(ITERATIONS*.95)-1]:.2f}")
print("FAISAL_EVIDENCE_INDEX_BENCHMARK_SCOPE=local_digest_and_schema_validation_without_external_authority")
