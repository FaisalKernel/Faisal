#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MODULE="$ROOT/tools/faisal-mcp-contract"
OUT=${1:-"$ROOT/../../build/frontier/mcp-contract-validation-2026-08-25"}
mkdir -p "$OUT"
python3 -m py_compile "$MODULE/faisal_mcp_contract.py" "$MODULE/test_faisal_mcp_contract.py"
python3 "$MODULE/test_faisal_mcp_contract.py" | tee "$OUT/selftest.log"
python3 - "$MODULE" "$OUT" <<'PY'
import hashlib
import json
import os
import sys
module, out = sys.argv[1:]
sys.path.insert(0, module)
from faisal_mcp_contract import ContractError, admit_tool_list, sha256_hex, validate_tool_call, validate_tool_result

def make_tool(name, output=False):
    d = {
        "name": name,
        "description": "bounded validation fixture",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 1}},
            "required": ["query"],
            "additionalProperties": False,
        },
    }
    if output:
        d["outputSchema"] = {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": False,
        }
    return d

tools = [make_tool("answer", True), make_tool("search")]
first = admit_tool_list("fixture-server", list(reversed(tools)), ["answer:write", "search:read"], maximum_tools=1, required_scopes={"fixture-server:answer": ["answer:write"], "fixture-server:search": ["search:read"]})
second = admit_tool_list("fixture-server", tools, ["answer:write", "search:read"], maximum_tools=1, cursor=first["nextCursor"], required_scopes={"fixture-server:answer": ["answer:write"], "fixture-server:search": ["search:read"]})
assert first["count"] == 1 and first["tools"][0]["name"] == "answer"
assert second["count"] == 1 and second["tools"][0]["name"] == "search" and second["nextCursor"] is None
validate_tool_call(make_tool("answer", True), {"query": "hello"})
validate_tool_result(make_tool("answer", True), {"answer": "world"})
negative = {}
try:
    validate_tool_call(make_tool("answer", True), {"query": ""})
except ContractError as exc:
    negative["invalid_input_rejected"] = str(exc)
try:
    validate_tool_result(make_tool("answer", True), {"wrong": "world"})
except ContractError as exc:
    negative["invalid_output_rejected"] = str(exc)
try:
    bad = make_tool("bad")
    bad["inputSchema"]["type"] = "function"
    admit_tool_list("fixture-server", [bad], [])
except ContractError as exc:
    negative["invalid_schema_rejected"] = str(exc)
assert len(negative) == 3
payload = {
    "schema": "FAISAL-MCP-CONTRACT-VALIDATION-1",
    "module": "tools/faisal-mcp-contract/faisal_mcp_contract.py",
    "server": "fixture-server",
    "deterministic_ordering": True,
    "scope_filtering": True,
    "opaque_pagination": True,
    "input_validation": True,
    "output_validation": True,
    "annotations_are_untrusted": True,
    "positive_page_digest": first["digest"],
    "negative_cases": negative,
}
raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
payload["record_digest"] = hashlib.sha256(raw).hexdigest()
with open(os.path.join(out, "mcp-contract-validation.json"), "w", encoding="utf-8") as h:
    json.dump(payload, h, indent=2, sort_keys=True)
    h.write("\n")
print("FAISAL_MCP_CONTRACT_VALIDATION_OK")
print("FAISAL_MCP_CONTRACT_RECORD", os.path.join(out, "mcp-contract-validation.json"))
print("FAISAL_MCP_CONTRACT_RECORD_DIGEST", payload["record_digest"])
PY
printf 'MCP_CONTRACT_VALIDATION_MARKER\n' > "$OUT/validation.marker"
