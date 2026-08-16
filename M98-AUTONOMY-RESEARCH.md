# FAISAL autonomy requirements research — 2026-08-16

## Research objective

Identify current-world requirements that FAISAL must satisfy for persistent autonomous operation, then choose an executable next dependency rather than claiming general autonomy from isolated primitives.

## Current verified baseline from FAISAL M97

FAISAL has validated low-level and userspace foundations for lifecycle identity, scoped authority leases, durable tasks, causal branches, evidence-complete commits, invalidation, replay, corruption fail-closed behavior, and Continuity Capsules that reject stale working/world/resource state. The complete system remains unfinished: there is no single mission supervisor yet that continuously selects durable work, evaluates progress, handles events, invokes capability-scoped tools, and recovers under policy.

## Source trail

1. HORIZON, “The Long-Horizon Task Mirage? Diagnosing Where and Why Agentic Systems Break,” https://arxiv.org/html/2604.11978v1. The source reports structural long-horizon degradation, with planning- and memory-related failures becoming dominant as horizons increase. This supports persistent state, verification, and recovery as first-class requirements rather than relying on larger context windows.

2. Linux kernel Heterogeneous Memory Management documentation, https://docs.kernel.org/mm/hmm.html. Linux already provides device-memory integration, shared virtual memory helpers, page-table mirroring, migration helpers, and accounting. FAISAL must not merely rename HMM; its new layer must provide an autonomy-level contract above these mechanisms.

3. USENIX OSDI 2024 CXL memory-tiering study, https://www.usenix.org/conference/osdi24/presentation/zhong-yuhong. Current tiering systems address capacity and placement but can suffer from contention and application-oblivious decisions. Autonomous operation therefore needs explicit resource admission and state-aware recovery.

4. IEA, “Key Questions on Energy and AI,” https://www.iea.org/reports/key-questions-on-energy-and-ai/executive-summary. The source documents rapidly increasing AI data-centre electricity demand, power density, and workload power swings. FAISAL autonomy must account for resource and energy budgets, not only task success.

5. U.S. government PDF, “Careful Adoption of Agentic AI Services,” https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF. Browser retrieval was attempted but the PDF did not expose readable text in the current browser session; no substantive claim is taken from the snippet until a text extraction succeeds.

## Initial gap hypothesis

The highest-value missing autonomy contract is a **Mission Supervisor / Autonomy Control Loop** above M95–M97: durable mission state, event-triggered wakeups, bounded planning cycles, capability-scoped tool admission, evidence requirements, continuity checks before resume, explicit stop/replan/escalate transitions, and independent policy approval. The next implementation must remain a deterministic service contract; model output may propose plans but cannot authorize actions.

## Verified autonomy requirements from current sources

6. Rabanser et al., “Towards a Science of AI Agent Reliability,” https://arxiv.org/html/2602.16666v1. The paper argues that terminal success scores hide operational flaws and proposes four independent reliability dimensions: consistency, robustness, predictability, and safety. It reports only small reliability gains despite capability gains across evaluated agent models. The systems implication is that FAISAL needs runtime metrics, predictable degradation, uncertainty-triggered deferral/escalation, fault injection, and bounded consequence—not only goal completion.

7. “Careful adoption of agentic AI services,” co-authored by ASD ACSC, CISA, NSA, the Canadian Cyber Security Centre, NCSC-NZ, and NCSC-UK, official PDF: https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF. Text extraction succeeded via the official PDF. The guidance describes agents as systems combining models with tools, external data, memory, planning workflows, goals, triggers, privileges, and metrics. It emphasizes least privilege, per-invocation authorization rather than cached startup permissions, identity and impersonation controls, continuous monitoring, incident response, resilient design, segmentation, tool validation, and defenses against cascading multi-agent failures and resource exhaustion. It explicitly warns that model behavior can be unpredictable and that broad unrestricted access should not be granted.

8. NIST AI Agent Standards Initiative, https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative. NIST’s August 14, 2026 updated page states that the initiative targets trusted, interoperable, secure autonomous agents and identifies agent authentication/identity infrastructure, open protocols, and security evaluations as strategic priorities. This supports FAISAL’s M94 authority, M96 causal ledger, and the M98 tool-registry direction, but also shows that interoperability and agent identity remain active standards problems rather than solved facts.

## Recomputed autonomy gap

FAISAL currently has many enforceable pieces but lacks a single **Mission Autonomy Control Loop** that turns durable objectives into bounded repeated cycles of observe → plan proposal → authority admission → tool execution → evidence → evaluation → continue, replan, stop, or escalate. The next primitive should be a deterministic userspace mission supervisor contract composed from M95 durable tasks, M96 causal authority, M97 continuity capsules, M73 world-state snapshots, M74 model admission, and M75 tool supervision. It must support triggers, leases, per-invocation checks, risk/cost budgets, progress metrics, predictable stop modes, recovery, and independent approval without making the model an authority.

The first implementation should not attempt unrestricted self-modification or a general autonomous agent. It should implement one auditable mission state machine and demonstrate that it continues across a restart, rejects stale state, stops on budget/deadline/risk, and escalates when policy or evidence is insufficient.
