from __future__ import annotations

import statistics
import time

from faisal_delegation_chain import ChainPolicy, DelegationChainLedger, DelegationHop, UseRequest, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "agent_claim_is_authority": False,
    "credential_metadata_is_authority": False,
    "delegation_receipt_is_execution_authority": False,
    "delegation_receipt_is_policy_authority": False,
    "delegation_receipt_is_production_authority": False,
}
ROUTE = digest({"route": "task-1"})


def make_ledger():
    l = DelegationChainLedger(ChainPolicy("p", "v1", 7, "audience-tools", frozenset({"read:catalog", "write:draft"}), max_depth=4, max_ttl=120, max_execution_count=4))
    root = DelegationHop("chain-1", "root", "principal", "agent-a", None, frozenset({"read:catalog", "write:draft"}), "audience-tools", "task-1", ROUTE, 7, 10, 90, 4)
    rd = l.register_hop(root)
    l.register_hop(DelegationHop("chain-1", "child", "agent-a", "agent-b", rd, frozenset({"read:catalog"}), "audience-tools", "task-1", ROUTE, 7, 10, 80, 4))
    return l


def measure(fn, count=1000):
    values = []
    for i in range(count):
        start = time.perf_counter_ns()
        fn(i)
        values.append(time.perf_counter_ns() - start)
    return statistics.mean(values), statistics.quantiles(values, n=20)[18]


def main():
    def baseline(i):
        return UseRequest(f"use-{i}", "chain-1", "child", "audience-tools", "task-1", ROUTE, frozenset({"read:catalog"}), 7, 1, 20, 80, f"nonce-{i}")

    def verify(i):
        l = make_ledger()
        request = baseline(i)
        return l.admit_use(request, now=21, authority=AUTHORITY)

    for name, fn in (("baseline_ungoverned", baseline), ("chain_verify_admit", verify)):
        mean, p95 = measure(fn)
        print(f"FAISAL_DELEGATION_CHAIN_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
