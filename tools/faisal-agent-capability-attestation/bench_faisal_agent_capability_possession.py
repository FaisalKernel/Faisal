from __future__ import annotations

import time

from faisal_agent_capability_attestation import digest
from faisal_agent_capability_possession import (
    AgentCapabilityPossessionLedger,
    AgentCapabilityPossessionPolicy,
    AgentCapabilityPossessionRequest,
)


ITERATIONS = 1000
ATTESTATION = digest({"receipt": "benchmark-attestation"})
KEY = digest({"jwk": "benchmark-key"})
TARGET = digest({"method": "POST", "uri": "https://faisal.local/v1/research"})
NONCE = digest({"nonce": "benchmark-nonce"})
POLICY = AgentCapabilityPossessionPolicy(
    "benchmark-policy", ATTESTATION, "agent/benchmark", KEY,
    frozenset(("research.read",)), 11, 100, 400,
)


def main() -> None:
    ledger = AgentCapabilityPossessionLedger(POLICY)
    started = time.perf_counter_ns()
    for number in range(ITERATIONS):
        proof = AgentCapabilityPossessionRequest(
            f"proof-{number}", ATTESTATION, "agent/benchmark", KEY, "research.read", "POST",
            TARGET, NONCE, 11, 120, 150,
        )
        ledger.present(
            proof,
            expected_method="POST",
            expected_target_digest=TARGET,
            expected_nonce_digest=NONCE,
            nonce_required=True,
            current_generation=11,
            authority={
                "model_output_is_authority": False,
                "agent_identity_is_execution_authority": False,
                "attestation_is_execution_authority": False,
                "attestation_is_policy_authority": False,
                "workload_selectors_are_hardware_proof": False,
                "production_approval": False,
            },
            now=121,
        )
    elapsed = time.perf_counter_ns() - started
    print(
        f"iterations={ITERATIONS} elapsed_ms={elapsed / 1_000_000:.3f} "
        f"per_possession_us={elapsed / ITERATIONS / 1_000:.3f} ledger_digest={ledger.ledger_digest()}"
    )


if __name__ == "__main__":
    main()
