# FAISAL M99 — Tool Registry and Execution Broker Benchmarks

**Status:** Validation-backed benchmark record

**Date:** 2026-08-16

## QEMU validation envelope

Three independent clean QEMU runs exercised boot, real ABI-38 tool authority, registry registration, duplicate rejection, model non-authority, invocation admission, revocation, risk policy denial, verified completion, unverified-result denial, concurrency, replay, and corruption failure.

| Run | Result | Wall time |
|---|---:|---:|
| Smoke 1 | Pass | 6,406 ms |
| Smoke 2 | Pass | 6,452 ms |
| Smoke 3 | Pass | 6,440 ms |
| **Minimum / maximum / mean** | **3/3 pass** | **6,406 / 6,452 / 6,432.67 ms** |

These times include QEMU and kernel boot and are retained as a reproducibility envelope. They are not isolated tool-call latency measurements.

## Direct versus governed local path

A four-iteration host benchmark compared two bounded journaled paths:

| Path | Mean per iteration | Total |
|---|---:|---:|
| Direct M98 causal completion without M99 registry admission | 3,304,042 ns | 13,216,170 ns |
| M99 registry, risk/cost/authority admission, invocation state, and M98 completion | 3,853,115 ns | 15,412,463 ns |

The governed path measured higher in this final run, but this result is **not interpreted as a performance regression claim either**. The paths use different journal files and are sensitive to filesystem cache state, service initialization, record mix, and measurement order. The benchmark proves only that both paths completed the same bounded fixture successfully. A publishable overhead comparison requires randomized order, warm/cold cache separation, many repetitions, CPU pinning, statistical confidence intervals, and equivalent external-tool work.

## Validation matrix

| Test | Result | Evidence |
|---|---:|---|
| Strict host build | Pass | `m99-host-compile-final.log` |
| Static build | Pass | `m99-static-compile-final.log` |
| Host selftest | Pass | `m99-host-final.log` |
| ASan/UBSan | Pass, exit 0 | `m99-asan-ubsan-final.log` |
| TSan | Pass, exit 0 | `m99-tsan-final.log` |
| Real-kernel QEMU | Pass, exit 0 | `m99-qemu-final.log` |
| Clean QEMU smokes | 3/3 pass | `m99-smokes.log` and `m99-smoke-*.log` |
| M95 durable-task regression | Pass | `m99-M95_DURABLE_QEMU.log` |
| M96 causal-authority regression | Pass | `m99-M96_CAUSAL_QEMU.log` |
| M90 key-provider regression | Pass | `m99-M90_KEY_PROVIDER_QEMU.log` |
| M91 provider-gate regression | Pass | `m99-M91_PROVIDER_GATE_QEMU.log` |
| Full FAISAL audit | 23/23 pass | `m99-full-audit.log` |
| Security pattern scan | Pass | `m99-security-scan.log` |

## Required future measurements

Before integrating real browser, filesystem, network, payment, deployment, or device tools, FAISAL must measure admission latency, revocation reaction time, denied-call rate, verification-failure detection time, audit bytes per invocation, registry lookup throughput, concurrent admission scaling, restart replay latency, and tool-adapter sandbox overhead. It must also benchmark a deliberately ungoverned fixture only in an isolated test environment, never against production side effects.

## Non-claims

M99 does not establish better agent task success, lower end-to-end tool latency, lower energy use, higher productivity, exactly-once remote effects, prompt-injection immunity, universal authorization, or production readiness. It does not prove that registered implementation digests describe the actual binary or that fixture results are truthful external observations.

## References

[1]: https://www.nccoe.nist.gov/news-insights/new-concept-paper-identity-and-authority-software-agents — NIST NCCoE identity and authorization concept paper.

[2]: https://www.cisa.gov/news-events/news/cisa-us-and-international-partners-release-guide-secure-adoption-agentic-ai — CISA agentic-AI security guidance announcement.
