#!/usr/bin/env python3
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_tool_authorization import InvocationRequest, ToolAdmissionLedger, ToolDescriptor, ToolGrant, digest


def fixtures(risk: str = "low"):
    descriptor = ToolDescriptor("server-1", "read_document", "https://mcp.example.test", digest({"tool": "read_document", "schema": 1}), ("mcp:tools", "docs:read"), risk, 4)
    grant = ToolGrant("grant-bench", "agent-1", descriptor.resource_uri, descriptor.descriptor_digest, ("mcp:tools", "docs:read"), 100, 200, 4, 1000, digest({"operator": "confirmed", "grant": "grant-bench"}), "low")
    return descriptor, grant


def request(descriptor, grant, i: int):
    return InvocationRequest(f"inv-{i}", "agent-1", descriptor.resource_uri, descriptor.tool_name, descriptor.descriptor_digest, ("docs:read",), digest({"doc": i}), "low", 120, 4)


def main(iterations: int = 1000) -> None:
    descriptor, grant = fixtures()
    means: list[int] = []
    for i in range(iterations):
        ledger = ToolAdmissionLedger()
        start = time.perf_counter_ns()
        ledger.admit(descriptor, grant, request(descriptor, grant, i), current_generation=4, now=130, nonce=f"nonce-{i}")
        means.append(time.perf_counter_ns() - start)
    print(f"FAISAL_TOOL_AUTH_BENCHMARK_ITERATIONS={iterations}")
    print(f"FAISAL_TOOL_AUTH_ADMISSION_MEAN_NS={statistics.mean(means):.2f}")
    print(f"FAISAL_TOOL_AUTH_ADMISSION_P95_NS={sorted(means)[int(iterations * 0.95) - 1]}")
    print("FAISAL_TOOL_AUTH_BENCHMARK_OK")
    print("FAISAL_TOOL_AUTH_BENCHMARK_SCOPE=local_python_authorization_receipts_not_oauth_network_or_tool_latency")


if __name__ == "__main__":
    main()
