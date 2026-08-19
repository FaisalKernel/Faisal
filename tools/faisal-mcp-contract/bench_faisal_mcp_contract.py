#!/usr/bin/env python3
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from faisal_mcp_contract import admit_tool_list

ITERATIONS = 5000

def make_tool(name, output=False):
    d = {
        "name": name,
        "description": "bounded benchmark fixture",
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
required = {"fixture-server:answer": ["answer:write"], "fixture-server:search": ["search:read"]}

def baseline():
    ordered = sorted(tools, key=lambda item: f"fixture-server:{item['name']}")
    projected = [{"name": item["name"], "description": item["description"], "inputSchema": item["inputSchema"], **({"outputSchema": item["outputSchema"]} if "outputSchema" in item else {}), "qualifiedName": f"fixture-server:{item['name']}"} for item in ordered]
    return json.dumps({"serverId": "fixture-server", "tools": projected}, sort_keys=True, separators=(",", ":"))

def validated():
    return admit_tool_list("fixture-server", tools, ["answer:write", "search:read"], required_scopes=required)["digest"]

def measure(fn):
    samples = []
    checksum = ""
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        checksum = fn()
        samples.append(time.perf_counter_ns() - start)
    return samples, checksum

base_samples, base_checksum = measure(baseline)
validated_samples, validated_checksum = measure(validated)
print(f"FAISAL_MCP_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_MCP_BENCHMARK_BASELINE_MEAN_NS={statistics.mean(base_samples):.2f}")
print(f"FAISAL_MCP_BENCHMARK_VALIDATED_MEAN_NS={statistics.mean(validated_samples):.2f}")
print(f"FAISAL_MCP_BENCHMARK_BASELINE_P95_NS={sorted(base_samples)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_MCP_BENCHMARK_VALIDATED_P95_NS={sorted(validated_samples)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_MCP_BENCHMARK_OVERHEAD_RATIO={statistics.mean(validated_samples) / statistics.mean(base_samples):.4f}")
print(f"FAISAL_MCP_BENCHMARK_BASELINE_CHECKSUM={base_checksum[:32]}")
print(f"FAISAL_MCP_BENCHMARK_VALIDATED_CHECKSUM={validated_checksum}")
print("FAISAL_MCP_BENCHMARK_SCOPE=local_two_tool_contract_validation_not_model_or_network_latency")
