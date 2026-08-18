# FAISAL Deterministic Plan Admission

## Purpose

The plan-admission contract is a bounded control-plane primitive between model-generated planning and durable task execution. It validates a proposed DAG before dispatch and produces deterministic execution metadata without executing tasks, granting capabilities, or authorizing external actions.

The contract computes a stable priority-then-node-ID topological order, earliest finish times, critical-path duration, minimum deadline slack, aggregate CPU and cost budgets, required capability coverage, highest risk, irreversible-node masks, and approval barriers. A plan digest binds the complete plan to the admission result.

## Admission rules

A plan must have the supported ABI, nonzero objective and generation, bounded node count, positive deadline and budgets, unique node IDs, known non-self dependencies, no duplicate dependency IDs, and available capabilities for every node. Cycles fail closed. Aggregate CPU/cost budgets and critical-path deadline constraints are checked before admission.

A plan marked as a model proposal requires explicit approval before execution. Any node above the approval risk threshold or marked irreversible also creates an approval barrier. The admission result reports barriers; it does not satisfy them. The existing handoff-approval lease is the composition point for transferring approved responsibility, and the durable execution/snapshot services remain responsible for persistence and recovery.

## Trust boundary

Model outputs, MCP task/skill metadata, tool descriptions, browser content, world observations, and planning text are untrusted data. Plan admission never turns those inputs into authority. It does not execute commands, call a model, access a browser, modify privileged kernel code, or approve irreversible actions. Approval must be supplied through an independent policy/authority path.

## Determinism and rollback

Given the same plan bytes, admission is deterministic. The digest allows later verification that the plan was not changed between planning and dispatch. The subsystem is isolated from the platform ABI and can be rolled back to the preceding `FAISAL-FRONTIER-HANDOFF-APPROVAL-LEASE-2026-08-21` checkpoint.

## Measurements

The benchmark compares validated 32-node DAG admission with a raw-plan pass-through loop. The validated path intentionally costs more because it performs dependency checks, topological sorting, critical-path analysis, budget aggregation, capability checks, approval-barrier calculation, and SHA-256 digest generation. This is control-plane safety overhead, not an end-to-end inference or agent-throughput claim.
