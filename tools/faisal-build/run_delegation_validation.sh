#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-"$ROOT/../../build/frontier/delegation-validation"}
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-delegation${PYTHONPATH:+:$PYTHONPATH}"
python3 "$ROOT/tools/faisal-delegation/test_faisal_delegation.py" | tee "$OUT/selftest.log"
python3 - "$OUT/delegation-validation.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
from faisal_delegation import DelegationError, DelegationScope, Invocation, authorize_invocation, derive_child, issue_root, verify_chain

out = Path(sys.argv[1])
scope = DelegationScope(frozenset({"read", "write"}), frozenset({"repo", "issues"}), frozenset(), 10)
root = issue_root(delegation_id="runner-root", issuer="user", delegatee="planner", issued_at=100, expires_at=1000, scope=scope, max_depth=3, holder_proof_digest="sha256:" + "1" * 64, nonce="runner-root-nonce")
child_scope = DelegationScope(frozenset({"read"}), frozenset({"repo"}), frozenset(), 4)
child = derive_child(root, delegation_id="runner-child", delegatee="worker", issued_at=150, expires_at=800, scope=child_scope, holder_proof_digest="sha256:" + "2" * 64, nonce="runner-child-nonce")
assert verify_chain((root, child), now=200).delegation_id == "runner-child"
result = authorize_invocation((root, child), Invocation("read", "repo", None, "call-1"), now=200)
assert result["authorized"] and result["executed"] is False
negative = {}
for name, fn in {
    "revoked_root": lambda: verify_chain((root, child), now=200, revoked_ids=frozenset({"runner-root"})),
    "revoked_lineage": lambda: verify_chain((root, child), now=200, revoked_lineages=frozenset({root.record_digest()})),
    "out_of_scope_tool": lambda: authorize_invocation((root, child), Invocation("write", "repo", None, "call-2"), now=200),
    "call_budget": lambda: authorize_invocation((root, child), Invocation("read", "repo", None, "call-3", used_calls=4), now=200),
    "expired": lambda: verify_chain((root, child), now=800),
}.items():
    try:
        fn()
    except DelegationError as exc:
        negative[name] = str(exc)
assert len(negative) == 5
amplified = DelegationScope(frozenset({"read", "write"}), frozenset({"repo", "outside"}), frozenset(), 5)
try:
    derive_child(root, delegation_id="runner-wide", delegatee="bad", issued_at=150, expires_at=800, scope=amplified, holder_proof_digest="sha256:" + "3" * 64, nonce="runner-wide-nonce")
except DelegationError as exc:
    negative["amplification"] = str(exc)
assert len(negative) == 6
payload = {
    "schema": "FAISAL-DELEGATION-VALIDATION-1",
    "leaf_delegation_id": child.delegation_id,
    "root_digest": root.record_digest(),
    "leaf_digest": child.record_digest(),
    "authorized_invocation": result["authorized"],
    "negative_cases": negative,
    "authority_boundaries": {"proof_digest_is_signature": False, "model_output_is_authority": False, "delegation_is_execution": False, "production_approval": False},
    "limitations": ["proof digests are trusted-input placeholders, not production signatures", "no authorization server, tool, model, network, or side effect was contacted", "revocation sets are caller-supplied and require distribution by a trusted control plane", "this is not production approval"],
}
out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
print("FAISAL_DELEGATION_VALIDATION_OK")
print("FAISAL_DELEGATION_RECORD", out)
print("FAISAL_DELEGATION_RECORD_DIGEST", "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest())
PY
printf 'FAISAL_DELEGATION_OK\n' > "$OUT/validation.marker"
