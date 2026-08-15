# FAISAL M75 — Capability-Scoped Browser and Tool Broker

**Status:** Implemented and validated in two-vCPU QEMU.
**Kernel base:** Linux `v7.2-rc7`.
**FAISAL ABI:** 37.
**Scope:** Userspace browser/tool broker integrated with FAISAL capability grants, network policy, browser-session lifecycle, semantic action metadata, transfer scopes, cancellation, and M71 provenance-linked durable records.

## Implementation

M75 adds `tools/faisal-browser/faisal_browser_tool_service.c` and its header. The broker creates a scoped kernel capability grant containing browser control, network connect, and explicitly selected filesystem transfer rights, then applies a bounded network policy with audit, raw-socket denial, listen denial, byte accounting, and socket ceilings. A browser session is opened with the grant and the M71 agent capability.

The broker prefers semantic browser action flags and counts coordinate fallback separately. Navigation is allowed only for the configured URL scope hash. Upload and download actions require the configured transfer scope hash and an independent operator confirmation. Kernel browser action records retain page, locator, input, observation, result, and artifact hashes; successful actions are linked to M71 episodic records through the kernel event sequence.

The deterministic hostile-content fixture rejects instruction-shaped strings such as requests to ignore previous instructions, grant capabilities, reveal secrets, or execute privileged operations. The content is retained as hostile evidence and does not alter policy or kernel authority. The browser session can be queried, cancelled, and denied further actions after cancellation.

## Validation

The static service/selftest build passed with `-O2 -Wall -Wextra -Werror -Wno-cpp` and static OpenSSL EVP linkage. The two-vCPU QEMU harness passed all required markers.

```text
FAISAL_M75_BOOT_OK
M75_SCOPED_NETWORK_AND_GRANT_OK policy=1 grant=1
M75_BROWSER_OPEN_OK session=1
M75_SCOPE_DENIALS_OK
M75_PROMPT_INJECTION_RESISTANCE_OK
M75_ACTION_FUZZ_REJECT_OK iterations=64
M75_SEMANTIC_NAVIGATION_OK action=1 sequence=5
M75_UPLOAD_SCOPE_OK
M75_DOWNLOAD_SCOPE_OK
M75_BROWSER_QUERY_OK actions=3 semantic=3
M75_BROWSER_CANCEL_OK
M75_POST_CANCEL_DENIAL_OK
M75_SELFTEST_EXIT=0
FAISAL_M75_TEST_RC=0
```

Five repeated M75 QEMU smoke runs passed with wall times from 4.9309 to 5.1891 seconds. The full M64 and M66–M74 regression suite also passed, for eleven of eleven harnesses in the M75 run. No M75 failure marker, kernel panic, `BUG`, `Oops`, or general-protection failure was observed in the captured logs.

## Acceptance gates

| Gate | Result | Evidence |
|---|---|---|
| Semantic browser fixture | Pass | Semantic navigation and three semantic action counts |
| Network scope | Pass | Active bounded network policy and grant-backed browser session |
| Upload/download scope | Pass | Allowlisted scope hashes plus operator confirmation; out-of-scope and unconfirmed actions denied |
| Prompt-injection resistance | Pass | Hostile instruction-shaped content denied as data |
| Action fuzz boundary | Pass | 64 malformed action requests rejected |
| Provenance | Pass | Kernel event sequence and M71 memory capability returned for successful actions |
| Cancellation | Pass | Browser cancellation returns terminal state and post-cancel action denial |
| Build and boot | Pass | Strict static build and QEMU boot markers |
| Regression | Pass | M64 and M66–M74 harnesses |

## Explicit non-claims

M75 does **not** claim a general browser agent, semantic understanding, safe internet use, source verification, prompt-injection immunity in arbitrary deployments, tool safety, consciousness, or real-world action success. Browser records and page content are not proof that an interaction achieved its intended result. Model output and page text never equal kernel authorization. Production browser/tool deployment requires an independent trusted supervisor, operator approvals for sensitive actions, and additional browser-engine and filesystem/network sandbox validation.

## Evidence

The design contract is `M75-BROWSER-TOOL-DESIGN.md`; the security review is `M75-SECURITY-REVIEW.md`; benchmark limits are in `M75-BENCHMARKS.md`; machine-readable evidence is `tools/faisal-build/evidence/m75-browser-tool-validation.json`; and raw M75, regression, benchmark, and build logs are under `tools/faisal-build/evidence/`.
