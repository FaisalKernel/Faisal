# FAISAL M75 Capability-Scoped Browser and Tool Broker Design

## Scope

M75 implements a userspace browser/tool broker over the FAISAL browser-session, network-policy, capability, provenance, and event interfaces. It records semantic browser actions and observations as structured hashes and metadata. A real browser engine remains outside the kernel; M75 does not parse arbitrary web pages in kernel space or treat page text as trusted instructions.

## Trust boundaries

Browser content, downloads, uploads, navigation targets, accessibility labels, DOM text, screenshots, model proposals, and tool responses are untrusted data. The broker validates its own bounded action contract, applies policy before invoking a kernel browser action, and records the result with provenance. Prompt-injection-like text is retained as hostile content and cannot change the broker’s policy, kernel capability, or approval state.

| Input or actor | Trust level | Permitted effect |
|---|---|---|
| Web page or downloaded content | Untrusted | Observation fixture input; no policy mutation |
| Model/browser-agent proposal | Untrusted | Request a bounded semantic action; no direct ioctl authority |
| Broker policy | Trusted test policy | Allow or deny action kind, URL scope, and transfer scope |
| Kernel capability grant | Enforcing authority | Permit browser/session rights and required filesystem/network rights |
| Operator confirmation | Independent approval input | Required for upload and destructive/tool actions in the fixture |

## Action contract

The broker accepts bounded actions for navigation, DOM/accessibility observation, semantic click/type/scroll, screenshot, page-state observation, download, and upload. Semantic interaction flags are preferred. Coordinate fallback is accepted only when the policy explicitly allows it and is counted separately. Each action carries a page ID, locator/input/observation/result hashes, a bounded URL or scope hash, and an explicit policy decision.

Navigation requires an allowlisted URL scheme and host hash plus the kernel browser rights for browser control and network connect. Upload requires an allowlisted local scope hash, operator confirmation, and browser plus filesystem-write rights. Download requires an allowlisted destination scope hash, operator confirmation, and browser plus filesystem-read rights. The M75 fixture does not interpret arbitrary paths as safe; it compares bounded policy tokens.

## Kernel integration

The broker opens a FAISAL session through the M71 service, registers a light agent, and requests a narrowly scoped capability grant with browser control, network connect, and explicitly selected transfer rights. It opens a browser session with the returned grant ID, grant capability, and agent capability. It records semantic actions through `AGI_LC_BROWSER`, queries the session counters, and closes or cancels the session. It applies an independent network policy fixture to the broker’s current task using `AGI_LC_NETWORK_POLICY`, with bounded family/type/operation masks and socket/byte ceilings. The service never grants broader rights based on model output.

## Prompt-injection handling

The deterministic hostile-content fixture recognizes instruction-shaped content such as requests to ignore policy, reveal secrets, grant access, or execute privileged commands. Detection produces a `HOSTILE_CONTENT` classification and denial for the requested privileged action. The content remains evidence for higher-level review. It is not executed, copied into an approval field, or passed as a kernel authorization token. A page’s claim that it is a supervisor is not a supervisor approval.

## Provenance and cancellation

Each accepted or denied action is linked to the broker session, action count, kernel event sequence, policy decision, content hash, and M71 durable memory record. A cancelled browser session is terminal and cannot accept a later action. A query after close returns the terminal state for audit; it does not reopen the session.

## Explicit non-claims

M75 does not claim a general browser agent, semantic understanding, safe web browsing, prompt-injection immunity in arbitrary model/runtime integrations, source verification, internet research correctness, tool safety, consciousness, or authorization from model output. It provides a measured capability boundary and a deterministic hostile-content fixture. A kernel browser record is telemetry and control state, not proof that a page is safe or that a browser action achieved its intended real-world result.
