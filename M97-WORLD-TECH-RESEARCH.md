# FAISAL First-Principles Research — 2026-08-16

## Source 1: HORIZON long-horizon agent benchmark

URL: https://arxiv.org/html/2604.11978v1

The paper introduces HORIZON as a cross-domain diagnostic benchmark with 3,100+ trajectories across web, operating-system, embodied, and database domains. Its abstract reports that long-horizon degradation is structural, not merely a lower terminal success rate: planning-related failures and memory-related failures become dominant as horizon increases. The authors conclude that scaling base models alone is insufficient and that planning, memory, and execution-time control require method-level improvements.

Implication for FAISAL: the OS substrate should preserve causal execution state, memory lineage, verification state, and recoverable action boundaries so that a system service can diagnose and continue a long task without relying on a model context window or terminal-score-only evaluation.

## Source 2: Official Linux Heterogeneous Memory Management documentation

URL: https://docs.kernel.org/mm/hmm.html

The Linux documentation states that HMM provides infrastructure for non-conventional memory such as GPU onboard memory, specialized `struct page` support, optional shared virtual memory, CPU page-table mirroring, device-memory representation, migration, exclusive access, and memory-cgroup accounting. It describes the device-specific allocator problem and the need to integrate device memory into regular kernel paths.

Implication for FAISAL: a future memory innovation must not simply rename HMM or invent a vendor-specific allocator. A defensible new layer must add a semantic contract absent from HMM—such as causal residency commitments and verifiable movement rights—while composing with Linux page tables, migration helpers, device memory, and cgroups.

## Initial first-principles constraint

The central unsolved systems problem is not raw model execution. It is maintaining a **verifiable continuity of intent, state, memory residency, authority, and evidence across long-horizon work while compute and memory move across heterogeneous resources**. Any FAISAL innovation must be evaluated against this constraint and must beat a clearly defined baseline on a measurable workload; “world-first” language alone is not evidence.

## Source 3: International Energy Agency — Key Questions on Energy and AI

URL: https://www.iea.org/reports/key-questions-on-energy-and-ai/executive-summary

The IEA executive summary reports that global data-centre electricity demand grew 17% in 2025, AI-focused data-centre electricity consumption grew 50%, and AI server power density has risen sharply. It also notes that AI workloads create large and rapid power swings, making reliable energy storage and infrastructure coordination important.

Implication for FAISAL: a merely faster scheduler is insufficient. A future AGI substrate must make energy, thermal headroom, memory movement, and recovery cost part of execution admission and evidence. “Useful work per joule under fault and thermal constraints” is a stronger target than raw tokens per second.

## Source 4: USENIX OSDI 2024 — Managing Memory Tiers with CXL in Virtualized Environments

URL: https://www.usenix.org/conference/osdi24/presentation/zhong-yuhong

The study describes CXL memory tiering as a capacity and cost opportunity, but notes that CXL accesses have higher latency than local DRAM. It reports that hardware-managed tiering can be close to regular DRAM for most workloads while outliers suffer from tenant and intra-tenant contention; its Memstrata allocator reduces observed degradation for sensitive workloads in the evaluated prototype.

Implication for FAISAL: page-granular tiering and hardware tiering are useful baselines, but they are application-oblivious or only indirectly aware of workload semantics. FAISAL’s differentiator must be a measurable, capability-controlled contract for **why** a memory object is resident, what evidence permits migration or eviction, and how a long-horizon task can recover if its state crosses tiers.

## Refined constraint

Current world technology has strong components—kernel HMM, cgroup/resource controls, hardware memory tiering, durable task journals, and model-based agents—but these components do not form one verifiable continuity fabric. The research direction should target the missing cross-layer invariant instead of duplicating any single component.
