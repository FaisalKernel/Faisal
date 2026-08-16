# FAISAL M99 tool-governance research — 2026-08-16

## Research objective

Define the smallest FAISAL-native tool registry and execution broker needed to make M98 autonomy capable of safe real tool actions without turning model output into authority.

## Current verified sources

1. NIST NCCoE, “New Concept Paper on Identity and Authority of Software Agents,” https://www.nccoe.nist.gov/news-insights/new-concept-paper-identity-and-authority-software-agents. The official page requests use cases, challenges, standards, technologies, and detailed feedback on identification, authorization, auditing, non-repudiation, and controls against prompt injection. It frames software and AI agents as systems that autonomously perform tasks while accessing data, tools, and applications. M99 must therefore maintain agent identity, authority provenance, auditability, non-repudiation evidence, and prompt-injection-resistant tool boundaries.

2. CISA, ASD ACSC, and international partners, “CISA, US and International Partners Release Guide to Secure Adoption of Agentic AI,” https://www.cisa.gov/news-events/news/cisa-us-and-international-partners-release-guide-secure-adoption-agentic-ai. The official release identifies expanded attack surface, privilege creep, behavioral misalignment, and obscure event records as risks. Its actionable recommendations include avoiding broad or unrestricted access, beginning with low-risk/non-sensitive use cases, and integrating agent security into the organization’s existing security model and risk posture. The underlying joint guide further requires least privilege, identity protection, per-invocation checks, tool validation, continuous monitoring, segmentation, and resilient recovery.

3. NIST, “AI Agent Standards Initiative,” https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative. NIST identifies agent authentication and identity infrastructure, open protocols, and security evaluations as active priorities. M99 should remain a stable local contract with explicit provenance rather than pretending that a universal external agent standard already exists.

4. “Careful adoption of agentic AI services,” official multinational guidance, https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF. The guidance describes tools, external data, memory, planning workflows, goals, triggers, privileges, and metrics as agent components. It warns that static startup permissions, confused deputies, identity spoofing, prompt injection, tool-description manipulation, cascading failures, and resource exhaustion can amplify a single compromised component. It recommends per-invocation authorization and continuous monitoring.

## M99 requirement extraction

The tool broker must register a stable tool identity and immutable metadata: capability scope, accepted operation class, resource mask, risk class, cost estimate, provenance requirements, verification requirements, revocation generation, and whether independent supervisor/operator approval is required. A proposal from M98 must be matched to a registry entry and current continuity/causal state. The broker must create a fresh per-invocation admission record and must not execute a tool merely because a model selected it.

The first implementation boundary should be a deterministic userspace registry plus execution-admission broker. It should support registration, duplicate/conflicting metadata rejection, lookup, scoped admission, risk/cost budget checks, M94/M96/M97/M98 correlation, revocation, audit records, result verification, and fail-closed behavior. It should not yet execute arbitrary shell commands or external network calls; a scripted safe tool fixture can prove the contract without creating a privilege escalation path.

## Non-claims

This research does not establish a universal agent identity standard, secure remote tool execution, hardware-backed identity, prompt-injection immunity, truthful tool metadata, or production readiness. M99 must measure the security and latency overhead of governance against a deliberately bounded ungoverned fixture.
