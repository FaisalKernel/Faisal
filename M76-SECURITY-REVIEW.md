# FAISAL M76 Security Review

## Security scope

M76 is a bounded userspace coordinator that composes M72–M75 service contracts and exercises FAISAL light-agent, IPC, cancellation, reflection, observability, and checkpoint/recovery interfaces. It is not a privileged autonomous deployer. Model output, browser content, experience content, and world-state values remain untrusted data.

## Threat model

A compromised model, browser page, service stage, child agent, or malformed task request may attempt to bypass independent approval, impersonate another agent, inject an unauthorized IPC message, cancel another agent’s work, restore an unverified checkpoint, use monitoring as authority, or cause a production deployment without supervision.

| Threat | M76 control | Residual risk |
|---|---|---|
| Model/page output becomes deployment authority | Deployment gate requires separate supervisor and operator approvals plus explicit canary/security/regression flags | Production approval identity and attestation remain outside the fixture |
| Agent impersonation | Kernel light-agent IDs and capabilities are returned at registration and required for IPC endpoints and light messages | Cross-process multi-host identity is future work |
| Unauthorized IPC endpoint | Kernel validates source/target agent capabilities, channel capability, current task agent, queue fields, and bounded lengths | Inline IPC is intentionally limited; large-message orchestration needs future memory-region policy |
| Cancellation abuse | Kernel IPC cancel requires sender endpoint ownership and known queued message ID; M76 cancels only its own queued message | Hierarchical cancellation across independent service processes remains future work |
| Queue exhaustion | Channel queue is bounded to four in the fixture and the selftest exercises cancellation | Backpressure strategies for thousands of agents need stress testing |
| Stale service lineage | M76 activates each service session before use, preserves separate lineages, and does not claim one shared kernel session | More complex concurrent composition needs a dedicated supervisor process model |
| Recovery to tampered model state | M74 rollback requires checkpoint sequence, parent sequence, state digest, manifest digest, verification, and lineage match | Arbitrary accelerator/browser state is not restored by this fixture |
| Monitoring becomes authority | Reflection and observability fields are recorded as telemetry; they do not grant actions or approvals | Future policy engines must preserve telemetry/authority separation |
| Malformed task injection | 64 malformed requests and explicit nonce/reserved/failure-stage checks are rejected before execution | Full property fuzzing of every composed UAPI remains future work |
| Service-stage failure hides prior evidence | Completed M72–M75 records remain durable; failure report includes stage and recovery sequence | Durable records do not prove semantic correctness |

## Multi-agent authority boundary

The coordinator registers planner and verifier identities with the kernel and uses the returned capabilities for IPC. The kernel enforces channel ownership, source/target endpoint matching, current-agent identity, queue bounds, message length, type/schema presence, and message cancellation ownership. A received acknowledgement is accepted only after the target agent identity is selected and the kernel returns the authenticated message.

M76 does not grant child agents broad capabilities based on their role or model output. The test uses bounded resource masks and fixed roles. Any future browser, filesystem, network, device, or secret capability must be granted separately through the scoped M64/M75 contracts.

## Recovery and deployment review

The browser-stage failure fixture triggers a model checkpoint recovery path. M76 reattaches the model session before invoking rollback, so the kernel checks the correct lineage and verification state. The recovered state closes the deployment gate. Successful canary eligibility requires independent supervisor approval, operator approval, security pass, regression pass, and canary pass. Missing approval is denied before any service stage opens.

M76 does not replace a trusted deployment supervisor, does not write a production boot artifact, and does not autonomously replace the running kernel. Any future deployment controller must retain canary, monitoring, operator confirmation, rollback, and independent-supervisor gates.

## Review conclusion

The demonstrated M76 controls pass for bounded multi-agent identity, IPC endpoint authorization, queued-message cancellation, service-session lineage switching, checkpoint-aware recovery, monitoring without authority, malformed-task rejection, and deployment-gate separation. The milestone is an integration fixture, not proof of safe general autonomy or production-grade multi-agent orchestration.
