# FAISAL Frontier Technology Research

**Date:** 2026-08-16

## Initial findings

The current systems landscape already contains durable-execution products and workflow research. Their common problem boundary is not simply restarting a process; it is reconstructing workflow state, distinguishing orchestration durability from external side-effect semantics, and preserving evidence across retries. This means FAISAL must not market ordinary journaling as an unprecedented technology. A differentiated contribution should bind durable task state to kernel-enforced intent authority, resource budgets, provenance, and a replayable causal ledger.

The search also surfaced current long-horizon-agent evaluation work, including the 2026 HORIZON benchmark, which frames long-horizon tasks as multi-step, cross-domain executions whose failures need systematic diagnosis rather than a single final answer score. This supports measuring FAISAL with recovery ambiguity, duplicate-side-effect prevention, policy violations, evidence completeness, and useful-work completion—not only model accuracy.

Linux already provides strong lower-level precedents: cgroup v2 for hierarchical resource control, pidfds for stable task lifetime references, CRIU for checkpoint/restore, and workqueues for bounded asynchronous execution contexts. FAISAL should compose with these mechanisms rather than replace them. The novel layer should make causal intent, authority, resource state, and recovery evidence first-class across the task lifecycle.

## Sources located

1. [Restate — What is Durable Execution?](https://restate.dev/what-is-durable-execution)
2. [Temporal — The definitive guide to Durable Execution](https://temporal.io/blog/what-is-durable-execution)
3. [HORIZON — The Long-Horizon Task Mirage?](https://arxiv.org/html/2604.11978v1)
4. [ExoFlow — A universal workflow system for Exactly-Once DAGs](https://www.usenix.org/conference/osdi23/presentation/zhuang)
5. [Linux Kernel documentation — Control Group v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
6. [CRIU project](https://criu.org/Main_Page)
7. [Linux Kernel documentation — Workqueue](https://docs.kernel.org/core-api/workqueue.html)
8. [Linux man-pages — pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
9. [Linux man-pages — pidfd_send_signal(2)](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html)

## Frontier hypotheses to test

| Hypothesis | Measurable outcome | Baseline |
|---|---|---|
| Causal intent ledger reduces recovery ambiguity | Percentage of interrupted tasks whose next authorized action is unambiguous from recorded state | M95 task journal without causal branch records |
| Authority-bound replay prevents stale side effects | Duplicate or post-revocation external action attempts rejected in fault-injection tests | Conventional retrying task queue |
| Resource-aware admission improves useful work under contention | Successful objective completions per CPU-time unit at fixed policy and failure rate | FIFO or priority-only queue |
| Evidence-carrying completion improves auditability | Time and completeness of reconstructing agent, policy, resource, and source lineage | M95 journal plus ordinary service logs |
| Branchable execution reduces recovery cost | Time to resume a safe alternative after a failed branch without redoing valid work | Restart-from-last-checkpoint baseline |

## Verified primary-source findings

The HORIZON paper reports that long-horizon agent failure is not only a lower final success rate. It describes horizon-dependent failure composition, with planning and memory failures becoming more important as sequences lengthen, and argues for trajectory-grounded failure attribution rather than terminal-score-only evaluation. Its task characterization separates intrinsic horizon from inefficient repeated actions and identifies compositional depth and breadth as distinct complexity dimensions [10].

ExoFlow presents a directly relevant systems precedent: execution and recovery can be decoupled, and exactly-once workflow semantics can be layered separately from task execution. It also uses task annotations for nondeterminism and references for arbitrary inter-task communication [11]. FAISAL should not claim to invent durable execution; a differentiated layer would instead combine recovery semantics with kernel-enforced intent leases, resource budgets, agent lineage, and evidence-carrying side-effect authorization.

The official cgroup v2 documentation confirms that cgroups provide hierarchical process organization and resource distribution, with top-down containment and delegation rules. It also warns that moving processes across cgroups is relatively expensive and that stateful resources such as memory are not moved together with the process [12]. This supports an objective-aware admission layer that assigns a task to a resource domain before execution rather than repeatedly migrating it.

The pidfd documentation confirms that a pidfd is a stable file descriptor referring to a task, is pollable for termination, and avoids PID-reuse ambiguity. It is therefore the correct foundation for M96 provider supervision, but not a substitute for ownership, lease, or secret-reclamation policy [13].

## Refined frontier direction

The strongest defensible frontier direction is a **Causal Authority Fabric**: a replayable, branch-aware execution ledger where every proposed action is linked to an objective state, observation digest, dependency frontier, resource admission, capability/intent lease, and resulting evidence. The system should support speculative branches that can be invalidated without authorizing their side effects, then commit only an evidence-complete branch through a trusted supervisor. This is a research architecture, not yet a validated FAISAL feature.

The initial implementation target should be bounded and reversible: extend the M95 durable-task journal with causal branch records and an evidence-complete commit gate, while reusing M94 intent leases and refusing to execute any branch action unless its lease, objective generation, resource admission, and observation frontier match. Success should be measured against M95 using fault injection: ambiguity after restart, stale-branch rejection, post-revocation denial, duplicate side-effect prevention, and audit reconstruction time.

## References

[10]: https://arxiv.org/html/2604.11978v1 — Wang et al., “The Long-Horizon Task Mirage? Diagnosing Where and Why Agentic Systems Break,” arXiv, 2026.
[11]: https://www.usenix.org/conference/osdi23/presentation/zhuang — Zhuang et al., “ExoFlow: A Universal Workflow System for Exactly-Once DAGs,” OSDI 2023.
[12]: https://docs.kernel.org/admin-guide/cgroup-v2.html — Linux Kernel documentation, “Control Group v2.”
[13]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.
