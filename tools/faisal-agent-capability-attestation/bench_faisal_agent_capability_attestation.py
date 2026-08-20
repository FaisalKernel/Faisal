from time import perf_counter

from faisal_agent_capability_attestation import AgentCapabilityAttestationLedger, AgentCapabilityPolicy, AgentCapabilityRequest, digest


AUTH = {"model_output_is_authority": False, "agent_identity_is_execution_authority": False, "attestation_is_execution_authority": False, "attestation_is_policy_authority": False, "workload_selectors_are_hardware_proof": False, "production_approval": False}
PARENT = digest({"operator": "release-supervisor", "lease": 9})
SELECTORS = digest({"uid": 4242, "cgroup": "agent.slice", "image": "sha256:fixture"})
PURPOSE = digest({"objective": "bounded research", "task": "source review"})
POLICY = AgentCapabilityPolicy("benchmark", "faisal.local", "agent/research-1", "ephemeral", "agent/orchestrator-1", PARENT, SELECTORS, PURPOSE, frozenset(("research.read",)), 2, 11, 100, 400)


def main() -> None:
    iterations = 1000
    ledger = AgentCapabilityAttestationLedger(POLICY)
    started = perf_counter()
    for index in range(iterations):
        request = AgentCapabilityRequest(f"bench-{index}", "agent/research-1", "ephemeral", "agent/orchestrator-1", PARENT, SELECTORS, PURPOSE, frozenset(("research.read",)), 1, 11, 120)
        ledger.attest(request, current_generation=11, nonce=f"nonce-{index}", authority=AUTH, now=121)
    elapsed_ms = (perf_counter() - started) * 1000
    print(f"iterations={iterations} elapsed_ms={elapsed_ms:.3f} per_attestation_us={(elapsed_ms * 1000 / iterations):.3f} ledger_digest={ledger.ledger_digest()}")


if __name__ == "__main__":
    main()
