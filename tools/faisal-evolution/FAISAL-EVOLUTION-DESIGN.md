# FAISAL Verified Improvement Evolution

## Purpose

The evolution transaction is a bounded control-plane primitive for the attached autonomous-improvement loop. It turns a proposed upgrade into an auditable state machine:

```text
DRAFT → ISOLATED → VALIDATED → PROMOTED
                    │             │
                    └→ REJECTED   └→ ROLLED_BACK
```

A candidate binds a research digest, parent and source repository heads, baseline artifact digest, candidate artifact digest, evidence digest, measured baseline/candidate metric, reproducibility result, policy thresholds, and rollback tag. The journal is append-only, `fsync`-backed, and SHA-256 chain verified during replay.

## Promotion policy

A candidate must first be isolated. Validation records whether tests passed, whether results are reproducible, the candidate metric, evidence digest, and optional external approval digest. Improvement and regression are calculated in parts per million according to whether lower or higher metric values are better. Candidates are rejected when validation fails, reproducibility is missing when required, improvement is below policy, regression exceeds policy, or required approval is absent. Model-proposed candidates cannot self-authorize promotion; they require an approval digest supplied by a separate authority path.

Promotion requires a validated candidate, research and rollback bindings when required, reproducibility when required, and approval for model-proposed candidates. Rollback is explicit and produces a receipt containing the rollback reason digest. The transaction does not itself deploy code or modify privileged kernel text.

## Composition

The evolution transaction composes with the existing plan-admission, snapshot-index, handoff-lease, task/execution, candidate-manifest, SBOM, readiness-gate, and release-tag systems. Plan admission determines whether a proposed workload plan is safe to dispatch. The evolution transaction determines whether a bounded upgrade has sufficient measured evidence to promote. Existing sandbox, build, test, signing, and deployment systems remain responsible for their respective operations.

## Trust boundaries

Research text, model outputs, provider metadata, MCP resources/tools/prompts, browser content, generated code, benchmark claims, and approval descriptions are untrusted data. A digest authenticates bytes and continuity; it does not make model output authoritative or constitute independent human approval. No adaptive loop may modify privileged kernel code without an externally controlled, separately validated release process.

## Measurements and rollback

The benchmark compares the full evidence-bound lifecycle with a raw metric-comparison baseline. The full lifecycle is intentionally slower because it performs persistence, digesting, policy checks, approval gating, and receipt creation. The result is control-plane overhead, not an end-to-end AI performance claim. The previous tagged checkpoint is preserved as the rollback target, and candidates remain independently queryable after replay.
