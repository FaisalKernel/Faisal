#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MODULE="$ROOT/tools/faisal-model-routing"
OUT=${1:-"$ROOT/../../build/frontier/model-routing-validation-2026-08-27"}
mkdir -p "$OUT"
python3 -m py_compile "$MODULE/faisal_model_routing.py" "$MODULE/test_faisal_model_routing.py"
python3 "$MODULE/test_faisal_model_routing.py" | tee "$OUT/selftest.log"
python3 - "$MODULE" "$OUT" <<'PY'
import copy
import hashlib
import json
import os
import sys
module, out = sys.argv[1:]
sys.path.insert(0, module)
from faisal_model_routing import Endpoint, RouteRequest, RoutingContractError, plan_route, verify_route

def ep(eid, mid, *, health="healthy", generation=4, cost=10, latency=20, region="us-east", privacy="internal", caps=("text",), provider="local", active=0, maximum=4, cache=False):
    return Endpoint(endpoint_id=eid, model_id=mid, model_digest="sha256:" + eid, provider_class=provider, capabilities=frozenset(caps), privacy_class=privacy, region=region, max_context_tokens=8192, estimated_cost_milli=cost, estimated_latency_ms=latency, health=health, health_generation=generation, active_requests=active, max_concurrency=maximum, cache_hit=cache)

request = RouteRequest(request_id="runner-1", required_capability="text", privacy_class="confidential", context_tokens=1024, max_cost_milli=100, max_latency_ms=500, region="us-east", generation=4, preferred_models=("preferred",), max_fallbacks=2)
endpoints = [ep("slow", "slow", latency=100), ep("preferred", "preferred", cache=True, cost=20), ep("cheap", "cheap", cost=5, latency=30), ep("bad", "bad", health="unknown")]
route = plan_route(endpoints, request, trusted_provider_classes={"local"}, observed_at=20)
verified = verify_route(route, expected_request_id="runner-1", expected_generation=4)
assert route["primary"]["endpoint_id"] == "preferred"
assert verified["verified"] and len(route["fallbacks"]) == 2
negative = {}
try:
    verify_route(route, expected_request_id="runner-1", expected_generation=5)
except RoutingContractError as exc:
    negative["generation_fence"] = str(exc)
try:
    plan_route([ep("restricted", "restricted", privacy="restricted")], request, trusted_provider_classes={"local"})
except RoutingContractError as exc:
    negative["privacy_no_eligible"] = str(exc)
try:
    plan_route([ep("foreign", "foreign", provider="untrusted")], request, trusted_provider_classes={"local"})
except RoutingContractError as exc:
    negative["provider_no_eligible"] = str(exc)
try:
    tampered = copy.deepcopy(route)
    tampered["primary"]["model_id"] = "tampered"
    verify_route(tampered, expected_request_id="runner-1", expected_generation=4)
except RoutingContractError as exc:
    negative["digest_tamper"] = str(exc)
assert len(negative) == 4
payload = {
    "schema": "FAISAL-MODEL-ROUTING-VALIDATION-1",
    "module": "tools/faisal-model-routing/faisal_model_routing.py",
    "route_digest": route["route_digest"],
    "primary_endpoint": route["primary"]["endpoint_id"],
    "fallback_endpoint_ids": [x["endpoint_id"] for x in route["fallbacks"]],
    "verified": verified,
    "negative_cases": negative,
    "authority_boundaries": {
        "model_output_is_authority": False,
        "endpoint_metadata_is_authority": False,
        "fallbacks_are_executions": False,
        "provider_policy_is_caller_supplied": True,
        "production_approval": False,
    },
}
raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
payload["record_digest"] = hashlib.sha256(raw).hexdigest()
with open(os.path.join(out, "model-routing-validation.json"), "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
print("FAISAL_MODEL_ROUTING_VALIDATION_OK")
print("FAISAL_MODEL_ROUTING_RECORD", os.path.join(out, "model-routing-validation.json"))
print("FAISAL_MODEL_ROUTING_RECORD_DIGEST", payload["record_digest"])
PY
printf 'FAISAL_MODEL_ROUTING_VALIDATION_OK tests=passed fallback=passed health_capability_privacy=passed generation_fence=passed digest=passed\n' > "$OUT/validation.marker"
