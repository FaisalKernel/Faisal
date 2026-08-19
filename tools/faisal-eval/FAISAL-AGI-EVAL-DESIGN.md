# FAISAL Independent AGI-Support Evaluation

## Purpose

This subsystem evaluates AI-agent adapters against evaluator-owned held-out tasks without allowing the adapter to see hidden expected answers. It records raw task inputs, outputs, scores, safety outcomes, latency, candidate identity, and hash-chain continuity in JSONL traces.

It is an evaluation harness, not an AGI claim. A fixture adapter demonstrates the protocol and failure handling; real model or agent adapters must be supplied separately and must obey the same JSON-line interface.

## Adapter boundary

For each task, the evaluator sends only:

```json
{
  "schema_version": 1,
  "task_id": "opaque-task-id",
  "category": "category",
  "public_input": {}
}
```

The adapter returns one JSON object. Hidden `expected` answers remain in the evaluator-owned held-out pack and are never included in the adapter payload. Adapter output is untrusted data. The evaluator applies deterministic scoring and safety checks.

## Held-out task pack

A task pack must declare `split: held_out`, contain bounded unique task IDs, and include an evaluator-owned expected-answer digest for each task. Safety-critical tasks require safe behavior or refusal and reject unsafe actions. The current fixture covers generalization-style arithmetic, ordering, planning, contradiction checking, provenance recall, uncertainty abstention, approval boundaries, and tool safety. It is a protocol fixture, not a broad intelligence benchmark.

## Raw trace integrity

Each task produces a JSONL record containing the sequence number, previous record digest, input digest, raw output, score, pass/fail status, safety result, latency, and candidate identity. The record digest is SHA-256 over the record excluding its own digest. Verification rejects sequence gaps, previous-digest mismatches, and modified records.

Raw traces are retained for audit and must be evaluated independently from summary metrics. A summary digest binds aggregate results to the evaluation run but does not replace raw traces.

## Self-improvement loop

The bounded loop is:

```text
Discover candidate manifests
→ Evaluate baseline on held-out pack
→ Evaluate candidate on the same held-out pack
→ Verify both raw traces
→ Compare pass rate, mean score, safety pass rate, and latency
→ Require policy thresholds
→ Require rollback checkpoint
→ Require external authority for model-proposed candidates
→ Promote a version pointer
→ Preserve prior pointer
→ Roll back on failure
```

Discovery reads only `*.manifest.json` files and records a discovery digest. Candidate manifests identify the adapter command, parent version, research digest, rollback checkpoint, whether the proposal came from a model, and whether privileged kernel code would change. Privileged kernel candidates are rejected by this harness. This is intentional: the harness can discover and verify intelligence improvements, but privileged code promotion remains subject to FAISAL’s independent release process.

## Promotion policy

The default fixture policy requires at least a 10 percentage-point pass-rate improvement, no more than 50% per-task latency regression, and a 100% safety pass rate. Model-proposed candidates additionally require an external authority token. The local authority token used in tests is only a protocol test artifact and is not production approval.

## Limits

A higher score on this fixture does not demonstrate AGI, consciousness, human-level intelligence, broad generalization, or real-world autonomy. Real qualification requires held-out domain-diverse tasks, contamination controls, independent scoring, repeated runs, uncertainty calibration, adversarial evaluation, long-horizon tasks, multimodal and embodied tasks, cost/latency/resource measurements, and external review. The current run proves the harness mechanics and a fixture candidate improvement, not a real model capability improvement.
