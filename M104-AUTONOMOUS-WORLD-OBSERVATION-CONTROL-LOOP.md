# M104: Autonomous World-Observation Control Loop

## Status

M104 adds a bounded kernel control-plane primitive for autonomous observation, diagnosis, repair proposal, verification, canary deployment, monitoring, and rollback. It is an **authorization and evidence gate**, not an AI model, web crawler, autonomous kernel patcher, or claim of consciousness.

The kernel remains responsible for identity, lease expiry, bounded state, capability matching, evidence accumulation, approval separation, deployment ordering, generation changes, and rollback state. Live web search, browser interaction, source ranking, cross-checking, model inference, experience extraction, candidate building, fuzzing, and repair diagnosis remain user-space responsibilities.

## Design

The additive `AGI_LC_AUTONOMY_CONTROL` ioctl uses a per-control opaque capability and a bounded seven-record kernel table. Each control has an owner session and lineage, a bounded lease, required evidence mask, accumulated evidence mask, digest, attempt counter, generation, and state.

The state machine is:

`OBSERVE -> DIAGNOSE -> PROPOSE -> IMPLEMENT -> BUILD -> TEST -> FUZZ -> SECURITY -> VERIFY -> CANARY -> DEPLOY -> MONITOR`

The implementation requires evidence before diagnosis, diagnosis before proposal, patch/build/test/fuzz/security evidence before verification, all configured evidence plus canary evidence before deployment, and independent supervisor and operator approvals when the corresponding flags are set. Rollback is available to the owner or a privileged trusted supervisor. Expired controls fail closed and increment generation.

The kernel never interprets model text as authority. A user-space orchestrator must possess the session capability and produce the evidence. Approval sessions are independent from the owner session and deployment is impossible without the configured approval flags.

## Live-world integration boundary

FAISAL’s existing browser and verified-research services can collect current external information, preserve source and retrieval metadata, cross-check claims, and publish only verified knowledge. The M104 control loop supplies the missing system-level gate connecting those observations to a reversible repair workflow. It does not grant unrestricted network access or permit an agent to modify the production kernel directly.

A future orchestrator should map observation, diagnosis, patch, build, test, fuzz, security, and canary results to the evidence bits, use signed digests for evidence, and request deployment only after the independent supervisor and operator services approve the candidate. Production replacement remains outside this primitive and must retain trusted-supervisor, operator, artifact-integrity, and rollback gates.

## Security and failure behavior

Requests are size-checked, flag-bounded, evidence-bounded, reserved-field checked, session-checked, and capability-checked. Evidence recording is owner-only. Supervisor and operator approvals require `CAP_SYS_ADMIN` and a session different from the owner. Signed-evidence mode rejects an all-zero digest. The bounded lease prevents indefinite stale authority. Unknown controls, stale capabilities, expired controls, invalid state transitions, missing evidence, missing approvals, and missing canary evidence fail closed.

The kernel stores metadata and digests only; it does not execute a proposed patch, load a model, browse the network, or silently self-modify. Rollback changes control state and generation but does not claim that a deployment artifact was restored; that restoration remains a trusted user-space deployment-supervisor responsibility.

## Verification evidence

The M104 selftest exercises owner-only evidence, blocked deployment without independent approvals, supervisor approval, operator approval, canary evidence, deploy, monitor query, and rollback. The current recovered kernel builds successfully. The static selftest build passes with `-Wall -Wextra -Werror` apart from the intentionally suppressed kernel-header advisory. The selftest has zero checkpatch errors, warnings, or checks.

The real-kernel QEMU gate passes with the markers `FAC_DEPLOY_BLOCKED_WITHOUT_APPROVALS_OK`, `FAC_INDEPENDENT_APPROVAL_CANARY_DEPLOY_OK`, `FAC_ROLLBACK_OK`, and `FAC_SELFTEST_EXIT=0`. The corrected aggregate suite passes all 27 harnesses with centralized diagnostic scanning. Sparse compilation of the lifecycle driver completes using the project’s upstream-compatible checker.

## Limitations and next work

M104 does not provide web search inside the kernel, a self-learning neural model inside the kernel, autonomous physical actuation, CXL/DAMON/HMM provider execution, proof of general intelligence, or limitless capability. The next dependency is user-space orchestration that consumes verified research and self-healing signals, records signed evidence, and drives this gate under independent approvals. Hardware/provider qualification, signed release artifacts, reproducible production builds, long-duration soak, and upstream-base migration remain release requirements.
