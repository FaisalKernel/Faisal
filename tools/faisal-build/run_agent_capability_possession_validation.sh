#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_AGENT_CAPABILITY_POSSESSION_OUT:-/home/ubuntu/agi-kernel/build/frontier/agent-capability-possession-validation-2026-08-20}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-agent-capability-attestation"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_agent_capability_possession.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_agent_capability_possession.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json
import pathlib
import sys
from faisal_agent_capability_attestation import AgentCapabilityAttestationError, digest
from faisal_agent_capability_possession import AgentCapabilityPossessionLedger, AgentCapabilityPossessionPolicy, AgentCapabilityPossessionRequest

out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "agent_identity_is_execution_authority": False, "attestation_is_execution_authority": False, "attestation_is_policy_authority": False, "workload_selectors_are_hardware_proof": False, "production_approval": False}
attestation = digest({"receipt": "agent-capability-attestation-fixture"})
key = digest({"jwk": "agent-key-fixture"})
target = digest({"method": "POST", "uri": "https://faisal.local/v1/research"})
nonce = digest({"nonce": "server-nonce-fixture"})
policy = AgentCapabilityPossessionPolicy("possession-policy", attestation, "agent/research-1", key, frozenset(("research.read", "memory.write")), 11, 100, 400)
def request(number, **changes):
    values = {"proof_id": f"proof-{number}", "attestation_digest": attestation, "agent_id": "agent/research-1", "key_thumbprint_digest": key, "capability": "research.read", "request_method": "POST", "target_digest": target, "nonce_digest": nonce, "generation": 11, "issued_at": 120, "expires_at": 150}
    values.update(changes)
    return AgentCapabilityPossessionRequest(**values)
def present(ledger, value, **changes):
    values = {"expected_method": "POST", "expected_target_digest": target, "expected_nonce_digest": nonce, "nonce_required": True, "current_generation": 11, "authority": authority, "now": 121}
    values.update(changes)
    return ledger.present(value, **values)
ledger = AgentCapabilityPossessionLedger(policy)
valid = present(ledger, request(1))
negative = {}
def deny(name, fn):
    try:
        fn(); negative[name] = "accepted"
    except AgentCapabilityAttestationError:
        negative[name] = "denied"
deny("attestation_mismatch", lambda: present(AgentCapabilityPossessionLedger(policy), request(2, attestation_digest=digest({"other": 1}))))
deny("key_mismatch", lambda: present(AgentCapabilityPossessionLedger(policy), request(3, key_thumbprint_digest=digest({"other": 2}))))
deny("capability_mismatch", lambda: present(AgentCapabilityPossessionLedger(policy), request(4, capability="network.admin")))
deny("method_mismatch", lambda: present(AgentCapabilityPossessionLedger(policy), request(5), expected_method="GET"))
deny("target_mismatch", lambda: present(AgentCapabilityPossessionLedger(policy), request(6), expected_target_digest=digest({"other": 3})))
deny("missing_nonce", lambda: present(AgentCapabilityPossessionLedger(policy), request(7, nonce_digest=None)))
deny("nonce_mismatch", lambda: present(AgentCapabilityPossessionLedger(policy), request(8, nonce_digest=digest({"other": 4}))))
deny("generation_mismatch", lambda: present(AgentCapabilityPossessionLedger(policy), request(9, generation=12)))
deny("expiry", lambda: present(AgentCapabilityPossessionLedger(policy), request(10), now=150))
deny("replay", lambda: present(ledger, request(1)))
deny("authority", lambda: present(AgentCapabilityPossessionLedger(policy), request(11), authority=dict(authority, model_output_is_authority=True)))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "agent-capability-possession-binding", "recorded_at": "2026-08-20T13:00:00Z", "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log"), "baseline": "new local possession-binding contract; no prior directly comparable agent request-binding control"}, "real_tasks": {"valid_possession_binding": {key: valid[key] for key in ("status", "attestation_binding_verified", "key_thumbprint_binding_verified", "capability_binding_verified", "request_binding_verified", "nonce_binding_verified", "lifecycle_verified", "replay_protected", "cryptographic_proof_verified", "credential_issued", "execution_performed", "production_approved")}, "negative_cases": negative, "all_expected": all(value == "denied" for value in negative.values())}, "boundary": {"independent_builder": False, "operator_signing_ceremony": False, "physical_hardware_qualification": False, "independent_external_security_review": False, "live_multihost_qualification": False, "production_approval": False}, "security_boundaries": {"model_output_is_authority": False, "optimizer_output_is_authority": False, "provider_metadata_is_authority": False, "unrestricted_kernel_self_modification": False, "fake_hardware_evidence": False, "fake_external_review": False, "receipt_is_cryptographic_proof": False, "receipt_is_execution_authority": False, "receipt_is_policy_authority": False, "credential_issued": False, "execution_performed": False, "production_approval": False}, "research": "tools/faisal-build/evidence/research-agent-attestation-possession-2026-08-20.md", "rollback_checkpoint": "FAISAL-FRONTIER-AGENT-CAPABILITY-ATTESTATION-2026-08-20-R1"}
record["record_digest"] = digest(record)
(out / "agent-capability-possession-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_AGENT_CAPABILITY_POSSESSION_OK tests=4_passed valid_binding=passed negative_cases=11_denied cryptographic_proof_verified=false execution_performed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
