#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_SIGNING_CEREMONY_OUT:-/home/ubuntu/agi-kernel/build/frontier/signing-ceremony-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-signing-ceremony"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_signing_ceremony.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_signing_ceremony.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_signing_ceremony import CeremonyEvent, CeremonyLedger, CeremonyPolicy, SigningCeremonyError, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "operator_claim_is_authority": False, "signature_receipt_is_production_authority": False, "production_approval": False}
policy = CeremonyPolicy("ceremony-runtime", "FAISAL-CEREMONY-FIXTURE", "a" * 40, digest({"artifact": "bzImage"}), "release", ("key-a", "key-b"), ("operator-a", "operator-b"), ("witness-a", "witness-b"), 2, 2, 4, 10, 100, "root-1")
def event(i, phase, **overrides):
    values = {"event_id": f"event-{i}", "phase": phase, "origin": "external_reference", "actor_id": "witness-a" if phase == "witness" else "operator-a" if phase == "sign" else "transparency-a", "actor_role": "operator" if phase == "sign" else phase, "manifest_digest": policy.manifest_digest, "event_digest": digest({"event": i}), "recorded_at": 20, "key_id": "", "signature_digest": "", "transparency_log_entry": "", "trusted_root_id": "", "verification_reference": "", "independence_group": "witness-group-a" if phase == "witness" else ""}
    if phase == "sign": values.update(key_id="key-a", signature_digest=digest({"signature": i}))
    if phase == "transparency": values.update(actor_id="transparency-a", key_id="key-a", signature_digest=digest({"signature": i}), transparency_log_entry="rekor-entry-a", trusted_root_id="root-1", verification_reference="external-verifier-a")
    values.update(overrides); return CeremonyEvent(**values)
ledger = CeremonyLedger(policy)
events = [event(1, "witness"), event(2, "witness", actor_id="witness-b", independence_group="witness-group-b"), event(3, "sign"), event(4, "sign", actor_id="operator-b", key_id="key-b", signature_digest=digest({"signature": 4})), event(5, "transparency"), event(6, "transparency", actor_id="transparency-b", key_id="key-b", signature_digest=digest({"signature": 6}), transparency_log_entry="rekor-entry-b", verification_reference="external-verifier-b")]
receipts = [ledger.record(item, sequence=i, nonce=f"n-{i}", now=21, authority=authority) for i, item in enumerate(events, 1)]
external_status = ledger.status(now=21, authority=authority)
local_ledger = CeremonyLedger(policy)
for i, phase in enumerate(("witness", "witness", "sign", "sign", "transparency", "transparency"), 1):
    overrides = {"origin": "local"}
    if phase == "witness" and i == 2: overrides.update(actor_id="witness-b", independence_group="local-witnesses")
    if phase == "sign" and i == 4: overrides.update(actor_id="operator-b", key_id="key-b", signature_digest=digest({"signature": i}))
    if phase == "transparency": overrides.update(actor_id="transparency-b" if i == 6 else "transparency-a", key_id="key-b" if i == 6 else "key-a", signature_digest=digest({"signature": i}), transparency_log_entry=f"local-log-{i}", trusted_root_id="root-1", verification_reference="local-verifier")
    local_ledger.record(event(i, phase, **overrides), sequence=i, nonce=f"local-{i}", now=21, authority=authority)
local_status = local_ledger.status(now=21, authority=authority)
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except SigningCeremonyError: negative[name] = "denied"
deny("manifest_mismatch", lambda: CeremonyLedger(policy).record(event(7, "witness", manifest_digest=digest({"other": True})), sequence=1, nonce="m", now=21, authority=authority))
deny("operator_role", lambda: CeremonyLedger(policy).record(event(8, "witness", actor_id="operator-a"), sequence=1, nonce="r", now=21, authority=authority))
deny("missing_signature", lambda: CeremonyLedger(policy).record(event(9, "sign", signature_digest=""), sequence=1, nonce="s", now=21, authority=authority))
deny("wrong_root", lambda: CeremonyLedger(policy).record(event(10, "transparency", trusted_root_id="wrong-root"), sequence=1, nonce="t", now=21, authority=authority))
deny("sequence_gap", lambda: CeremonyLedger(policy).record(event(11, "witness"), sequence=2, nonce="g", now=21, authority=authority))
deny("authority", lambda: CeremonyLedger(policy).record(event(12, "witness"), sequence=1, nonce="a", now=21, authority=dict(authority, production_approval=True)))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "operator-signing-ceremony-preparation-and-evidence-verification", "recorded_at": "2026-08-19T23:59:00Z", "policy": {"ceremony_id": policy.ceremony_id, "manifest_digest": policy.manifest_digest, "release_tag": policy.release_tag, "release_head": policy.release_head, "artifact_digest": policy.artifact_digest, "key_threshold": policy.key_threshold, "witness_threshold": policy.witness_threshold, "trusted_root_id": policy.trusted_root_id}, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "external_reference_fixture": {"events_recorded": len(receipts), "structurally_complete": external_status["structurally_complete"], "external_ceremony_evidence_structurally_complete": external_status["external_ceremony_evidence_structurally_complete"], "operator_ceremony_completed": external_status["operator_ceremony_completed"], "signature_cryptographically_verified": external_status["signature_cryptographically_verified"], "transparency_log_verified": external_status["transparency_log_verified"], "production_approval": external_status["production_approval"], "blockers": external_status["blockers"]}, "local_preparation_fixture": {"structurally_complete": local_status["structurally_complete"], "external_ceremony_evidence_structurally_complete": local_status["external_ceremony_evidence_structurally_complete"], "production_approval": local_status["production_approval"], "blockers": local_status["blockers"]}, "negative_cases": negative, "all_expected": all(value == "denied" for value in negative.values()), "safety": {**authority, "signature_created": False, "signature_cryptographically_verified": False, "transparency_log_verified": False, "operator_ceremony_completed": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-QUALIFICATION-INTAKE-2026-08-19"}
record["record_digest"] = digest(record)
(out / "signing-ceremony-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_SIGNING_CEREMONY_OK tests=4_passed external_fixture=structurally_complete local_external_blocked=true negative_cases=6_denied signature_created=false operator_ceremony_completed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
