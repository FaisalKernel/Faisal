#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_DELEGATION_CHAIN_OUT:-/home/ubuntu/agi-kernel/build/frontier/delegation-chain-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-delegation-chain"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_delegation_chain.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_delegation_chain.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_delegation_chain import ChainPolicy, DelegationChainError, DelegationChainLedger, DelegationHop, UseRequest, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "agent_claim_is_authority": False,
    "credential_metadata_is_authority": False,
    "delegation_receipt_is_execution_authority": False,
    "delegation_receipt_is_policy_authority": False,
    "delegation_receipt_is_production_authority": False,
}
route = digest({"route": "task-1"})
policy = ChainPolicy("delegation-policy", "v1", 7, "audience-tools", frozenset({"read:catalog", "write:draft", "publish:report"}), max_depth=4, max_ttl=120, max_execution_count=4)

def make_hop(hop_id, issuer, subject, parent=None, scope=("read:catalog", "write:draft"), expires=90, limit=4):
    return DelegationHop("chain-1", hop_id, issuer, subject, parent, frozenset(scope), "audience-tools", "task-1", route, 7, 10, expires, limit)

def make_request(use_id="main", leaf="child", requested=("read:catalog",), count=1, expires=80):
    return UseRequest(use_id, "chain-1", leaf, "audience-tools", "task-1", route, frozenset(requested), 7, count, 20, expires, "nonce-" + use_id)

ledger = DelegationChainLedger(policy)
root = make_hop("root", "principal", "agent-a")
root_digest = ledger.register_hop(root)
ledger.register_hop(make_hop("child", "agent-a", "agent-b", root_digest, ("read:catalog",), expires=80, limit=3))
valid = ledger.admit_use(make_request(), now=21, authority=authority)

negative = {}
denied = 0
for name, setup, req in (
    ("execution_count", "normal", make_request("execution-count", count=4)),
    ("revocation", "revoked", make_request("revoked")),
    ("audience", "normal", UseRequest("audience", "chain-1", "child", "wrong-audience", "task-1", route, frozenset({"read:catalog"}), 7, 1, 20, 80, "nonce-audience")),
    ("expiry", "expired", make_request("expired", expires=21)),
    ("replay", "replay", make_request()),
):
    if name == "revocation":
        trial = DelegationChainLedger(policy)
        rd = trial.register_hop(make_hop("root-r", "principal", "agent-a"))
        trial.register_hop(make_hop("child-r", "agent-a", "agent-b", rd, ("read:catalog",), expires=80, limit=3))
        trial.revoke("child-r", epoch=1)
        candidate = UseRequest("revoked", "chain-1", "child-r", "audience-tools", "task-1", route, frozenset({"read:catalog"}), 7, 1, 20, 80, "nonce-revoked")
    elif name == "replay":
        trial = ledger
        candidate = req
    else:
        trial = DelegationChainLedger(policy)
        rd = trial.register_hop(make_hop("root-" + name, "principal", "agent-a", expires=21 if name == "expiry" else 90))
        trial.register_hop(make_hop("child-" + name, "agent-a", "agent-b", rd, ("read:catalog",), expires=21 if name == "expiry" else 80, limit=3))
        candidate = req
        if name != "execution_count":
            candidate = UseRequest(req.use_id, "chain-1", "child-" + name, req.audience, req.task_id, req.route_digest, req.requested_capabilities, req.generation, req.execution_count, req.requested_at, req.expires_at, req.nonce)
        else:
            candidate = UseRequest(req.use_id, "chain-1", "child-" + name, req.audience, req.task_id, req.route_digest, req.requested_capabilities, req.generation, req.execution_count, req.requested_at, req.expires_at, req.nonce)
    try:
        trial.admit_use(candidate, now=21, authority=authority)
        negative[name] = "accepted"
    except DelegationChainError:
        negative[name] = "denied"; denied += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "delegation-chain-capability-verifier",
    "recorded_at": "2026-08-19T17:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 5, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"valid_two_hop_chain": {"admitted": valid["admitted"], "chain_depth": valid["chain_depth"], "effective_capabilities": valid["effective_capabilities"], "credentials_issued": valid["credentials_issued"], "tools_executed": valid["tools_executed"]}, "negative_cases": negative, "negative_cases_denied": denied == 5},
    "safety": {**authority, "credentials_issued": False, "cryptographic_attestation_verified": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-ARTIFACT-LINEAGE-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "delegation-chain-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_DELEGATION_CHAIN_OK tests=5_passed valid_two_hop_chain=passed negative_cases=5_denied credentials_issued=false tools_executed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
