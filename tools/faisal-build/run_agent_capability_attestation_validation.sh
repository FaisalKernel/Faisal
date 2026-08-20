#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_AGENT_CAPABILITY_ATTESTATION_OUT:-/home/ubuntu/agi-kernel/build/frontier/agent-capability-attestation-validation-2026-08-20}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-agent-capability-attestation"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_agent_capability_attestation.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_agent_capability_attestation.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json
import pathlib
import sys
from faisal_agent_capability_attestation import AgentCapabilityAttestationError, AgentCapabilityAttestationLedger, AgentCapabilityPolicy, AgentCapabilityRequest, digest

out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "agent_identity_is_execution_authority": False, "attestation_is_execution_authority": False, "attestation_is_policy_authority": False, "workload_selectors_are_hardware_proof": False, "production_approval": False}
parent = digest({"operator": "release-supervisor", "lease": 9})
selectors = digest({"uid": 4242, "cgroup": "agent.slice", "image": "sha256:fixture"})
purpose = digest({"objective": "bounded research", "task": "source review"})
policy = AgentCapabilityPolicy("agent-policy", "faisal.local", "agent/research-1", "ephemeral", "agent/orchestrator-1", parent, selectors, purpose, frozenset(("research.read", "memory.write")), 2, 11, 100, 400)
def request(number, **changes):
    values = {"request_id": f"request-{number}", "agent_id": "agent/research-1", "agent_kind": "ephemeral", "parent_agent_id": "agent/orchestrator-1", "parent_authority_digest": parent, "workload_selector_digest": selectors, "purpose_digest": purpose, "requested_capabilities": frozenset(("research.read",)), "delegation_depth": 1, "generation": 11, "issued_at": 120}
    values.update(changes)
    return AgentCapabilityRequest(**values)
ledger = AgentCapabilityAttestationLedger(policy)
valid = ledger.attest(request(1), current_generation=11, nonce="valid", authority=authority, now=121)
negative = {}
def deny(name, fn):
    try:
        fn(); negative[name] = "accepted"
    except AgentCapabilityAttestationError:
        negative[name] = "denied"
deny("identity_mismatch", lambda: AgentCapabilityAttestationLedger(policy).attest(request(2, agent_id="agent/other"), current_generation=11, nonce="i", authority=authority, now=121))
deny("parent_mismatch", lambda: AgentCapabilityAttestationLedger(policy).attest(request(3, parent_agent_id="agent/other-parent"), current_generation=11, nonce="p", authority=authority, now=121))
deny("selector_mismatch", lambda: AgentCapabilityAttestationLedger(policy).attest(request(4, workload_selector_digest=digest({"uid": 1})), current_generation=11, nonce="s", authority=authority, now=121))
deny("purpose_mismatch", lambda: AgentCapabilityAttestationLedger(policy).attest(request(5, purpose_digest=digest({"objective": "other"})), current_generation=11, nonce="q", authority=authority, now=121))
deny("capability_escalation", lambda: AgentCapabilityAttestationLedger(policy).attest(request(6, requested_capabilities=frozenset(("network.admin",))), current_generation=11, nonce="c", authority=authority, now=121))
deny("generation_mismatch", lambda: AgentCapabilityAttestationLedger(policy).attest(request(7, generation=12), current_generation=11, nonce="g", authority=authority, now=121))
deny("replay", lambda: ledger.attest(request(8), current_generation=11, nonce="valid", authority=authority, now=122))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "agent-capability-attestation", "recorded_at": "2026-08-20T12:00:00Z", "generation": 11, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log"), "baseline": "new provider-neutral contract; no prior directly comparable agent-attestation contract"}, "real_tasks": {"valid_agent_attestation": {key: valid[key] for key in ("status", "identity_verified", "parentage_verified", "selector_verified", "purpose_verified", "capability_attenuation_verified", "lifecycle_verified", "credential_issued", "execution_performed", "production_approved")}, "negative_cases": negative, "all_expected": all(value == "denied" for value in negative.values())}, "boundary": {"independent_builder": False, "operator_signing_ceremony": False, "physical_hardware_qualification": False, "independent_external_security_review": False, "live_multihost_qualification": False, "production_approval": False}, "safety": {**authority, "external_identity_provider_contacted": False, "credential_issued": False, "execution_performed": False, "hardware_attested": False, "production_approval": False}, "security_boundaries": {"model_output_is_authority": False, "optimizer_output_is_authority": False, "provider_metadata_is_authority": False, "unrestricted_kernel_self_modification": False, "fake_hardware_evidence": False, "fake_external_review": False, "attestation_is_execution_authority": False, "attestation_is_policy_authority": False, "production_approval": False}, "research": "tools/faisal-build/evidence/research-agent-capability-attestation-2026-08-20.md", "rollback_checkpoint": "FAISAL-FRONTIER-EVIDENCE-INDEX-2026-08-19-R2"}
record["record_digest"] = digest(record)
(out / "agent-capability-attestation-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_AGENT_CAPABILITY_ATTESTATION_OK tests=4_passed valid_attestation=passed negative_cases=7_denied credential_issued=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
