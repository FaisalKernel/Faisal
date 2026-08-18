# FAISAL Progressive Tool-Context Admission

## Purpose

The progressive tool-context subsystem bounds the amount of MCP-like tool metadata and result metadata admitted to a model-facing control-plane request. It is a **userspace/reference contract**, not an MCP implementation, browser driver, inference engine, or privileged kernel authority.

## Contract

A registry records function, resource, or prompt tools with a server/name identity, capability mask, trust level, bounded schema, result-size hint, registry generation, and SHA-256 definition digest. A request supplies a sequence, generation, required capabilities, minimum trust, maximum tool count, definition-byte budget, result-byte budget, and non-authoritative flags.

Admission is deterministic registry-order filtering. A tool is admitted only when its generation, capability mask, trust level, definition bytes, and result-size hint fit the request. The result is a selected-ID list plus byte counters and an admission digest. A receipt binds the request sequence, generation, counters, and admission digest. Any counter, digest, or generation mutation is rejected.

Result projection records only original and projected sizes and their digests. It does not return payload contents. This lets a higher-level sandbox or broker decide what data may be returned to a model while keeping the admission layer bounded and auditable.

## Security and authority boundaries

Tool descriptions, provider metadata, model proposals, browser page content, and projected results are **data**, not authority. The subsystem does not authorize tool execution, secrets access, browser actions, model selection, privileged kernel changes, or external side effects. Stale generations, malformed budgets, oversized results, and receipt tampering fail closed.

`FTC_FLAG_MODEL_PROPOSAL` and `FTC_FLAG_VERIFIED_INPUT` are provenance metadata only. The presence of either flag cannot grant authority. A future integration must bind the receipt to an existing capability broker, safety control plane, sandbox, and immutable audit path.

## Rollback and lifecycle

The implementation is isolated under `tools/faisal-tool-context/` and does not change the Linux or FAISAL platform ABI. The pre-upgrade M248 tag is the rollback checkpoint. The validation runner is independently executable and reports explicit self-test, fuzz, ASan/UBSan, ThreadSanitizer, benchmark, and adjacent-regression markers.

## Measurement interpretation

The deterministic eight-tool fixture admitted 3,040,000 definition bytes over 20,000 requests versus 11,820,000 bytes for full-manifest exposure, a 74.2% reduction. The progressive path measured 898.70 ns/request in the local fixture and the simple baseline scan measured 3.81 ns/request. The baseline is not an inference engine and the result is not a claim about tokens/second, end-to-end latency, cost, or model quality.
