# FAISAL Autonomous Control-Plane Research

**Accessed:** 2026-08-17

## Research conclusions

### Continuous AI risk management

NIST describes the AI Risk Management Framework as a lifecycle framework for improving trustworthiness and managing risks in AI systems. Its public overview organizes work around Govern, Map, Measure, and Manage, and NIST’s 2026 critical-infrastructure concept note emphasizes applying trustworthy-AI practices to AI-enabled capabilities. Source: https://www.nist.gov/itl/ai-risk-management-framework

**FAISAL impact:** an autonomous world-observation and repair loop must continuously collect evidence, measure health, manage risk, and require explicit authorization for consequential changes. A self-learning loop must preserve provenance and distinguish retained experience from model retraining.

### Watchdog-based liveness and recovery

The Linux watchdog API documents a userspace daemon that periodically notifies `/dev/watchdog`; if notifications stop because userspace or the kernel fails, the hardware watchdog can reset the machine. The API also exposes timeout, pretimeout, boot status, and environmental status where supported. Source: https://docs.kernel.org/watchdog/watchdog-api.html

**FAISAL impact:** liveness should be supervised independently from the model and the repair service. A model must not be able to disable the last-resort recovery path. FAISAL’s current deployment-supervisor primitives should be extended with leases, health evidence, bounded recovery actions, and rollback state—not an unrestricted self-modifying kernel.

### Checkpoint/restore boundary

CRIU provides userspace checkpoint/restore for Linux processes and containers, including migration and debugging use cases, but explicitly documents that it cannot save and restore every bit of task state. Source: https://criu.org/Main_Page

**FAISAL impact:** autonomous repair must use verifiable checkpoints and continuation capsules, and must fail closed when state is not restorable. It cannot claim universal recovery from arbitrary hardware or kernel failures.

### Signed provenance and reproducible release evidence

SLSA’s build track describes increasing guarantees: provenance at Build L1, signed provenance from a hosted build platform at Build L2, and hardened build isolation at Build L3. The current SLSA site identifies version 1.2 as current and the referenced v1.1 levels page as retired. Source: https://slsa.dev/spec/v1.1/levels

**FAISAL impact:** autonomous repair proposals must produce immutable provenance, test evidence, and artifact hashes. Production deployment must verify signatures and policy gates independently of the model.

## Selected next capability

The highest-value unblocked capability is a **kernel-backed autonomous control-loop lease and evidence gate**. It should connect observation, diagnosis, repair proposal, build/test evidence, canary state, deployment authorization, monitoring, and rollback into a bounded state machine. The kernel records state transitions and enforces lease expiry, lineage, capability checks, evidence digests, and independent approval bits. User-space services perform web retrieval, source verification, diagnosis, patch generation, builds, fuzzing, and model/skill updates. The kernel never executes web content, retrains a model, or treats model output as authority.

This is more valuable and safer than embedding a self-learning model in kernel space. It turns “autonomy” into an executable, measurable, reversible operating-system control primitive while preserving Linux’s existing watchdog, checkpoint, namespace, LSM, and deployment mechanisms.
