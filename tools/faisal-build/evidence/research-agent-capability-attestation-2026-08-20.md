# Research note: agent capability attestation

Date: 2026-08-20

## Primary-source findings

SPIRE documents a separation between node attestation, workload attestation, identity issuance, and workload registration. It identifies workloads by comparing discovered process or platform selectors with registered selectors, and returns a short-lived SVID only when the entry matches. A registration entry carries a workload identity, selectors, and a parent identity. Sources: [SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/) and [SPIRE workload registration](https://spiffe.io/docs/latest/deploying/registering/).

HashiCorp’s current SPIFFE guidance distinguishes identity, authorization, and credential brokering. A valid workload identity alone does not determine what a workload may do; a separate policy decision is required. Source: [HashiCorp Vault and SPIFFE](https://www.hashicorp.com/en/blog/implementing-workload-identity-with-hashicorp-vault-and-spiffe).

The Cloud Security Alliance Agent Identity Governance Framework describes autonomous, orchestrator, and ephemeral sub-agent identities as distinct lifecycle classes. Its draft recommends parentage, bounded scope, expiration, constrained delegation, sponsor/accountability records, and revocation for agent identities. Source: [CSA AIGF](https://labs.cloudsecurityalliance.org/agentic/agentic-identity-governance-framework-v1/).

## FAISAL implication

FAISAL already has tool attestation, intent-bound authority leases, trace certification, and capability/provenance primitives. A non-duplicative upgrade is a provider-neutral **agent capability attestation contract** that binds an agent lifecycle identity to a parent authority, exact workload selectors supplied as evidence, a bounded purpose digest, expiration, revocation generation, and explicit non-authority semantics. It must not claim hardware, SPIFFE/SPIRE interoperability, cryptographic SVID issuance, or live provider execution.
