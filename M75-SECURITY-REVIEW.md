# FAISAL M75 Security Review

## Security scope

M75 is a userspace browser/tool broker above FAISAL ABI 37. It uses a kernel capability grant, network-policy record, browser-session record, event sequence, and M71 durable memory record. The broker does not contain a browser engine and does not trust page content, downloads, uploads, model output, or accessibility/DOM text as authority.

## Threat model

A compromised model, malicious webpage, prompt-injection payload, hostile download, or buggy tool adapter may attempt to make the broker grant capabilities, navigate outside scope, upload or download arbitrary files, use raw sockets or listeners, bypass operator confirmation, continue after cancellation, or hide provenance.

| Threat | M75 control | Residual risk |
|---|---|---|
| Page text changes policy | Hostile instruction-shaped content is classified and denied before kernel action; content is not parsed as policy | Detection is a deterministic fixture, not complete prompt-injection protection |
| Model requests privileged browser action | Only broker policy and existing kernel grant fields reach `AGI_LC_BROWSER`; model text is data | Production model adapters need independent supervisor isolation |
| Network escape | Kernel network policy restricts families/types/operations, denies raw sockets/listen, audits bytes, and caps sockets | Exact destination allowlisting requires a production network policy layer beyond this ABI fixture |
| Unscoped upload/download | Upload/download require distinct scope hashes and operator confirmation; kernel rights are required | The fixture uses scope tokens, not a full filesystem path broker |
| Overbroad browser grant | Grant rights are limited to browser control, network connect, and transfer rights; sandbox flags include user/network/cgroup/seccomp boundaries | Grant creation depends on trusted authority and CAP_SYS_ADMIN in the current test environment |
| Coordinate automation abuse | Semantic flags are preferred; coordinate fallback is disabled by default and counted separately | A future browser service must validate accessibility/DOM semantics independently |
| Action replay after cancellation | Kernel browser session becomes terminal; service rejects post-cancel actions | Cross-process broker identity and restart recovery need a later service contract |
| Provenance loss | Successful actions include kernel event sequence and M71 memory record capability; policy generation is retained | Semantic truth and real-world outcome are not proved by provenance |
| Malformed action metadata | 64 invalid kind/reserved-field requests are denied before kernel record submission | Full ABI property fuzzing remains future work |

## Authority boundary

The broker’s capability grant is created by a kernel-validated trusted authority path and is bound to the M71 light-agent identity. Browser actions require matching grant ID, grant capability, and agent capability. The broker does not derive a capability from a URL, DOM node, screenshot, model response, page instruction, or operator-facing text. The `proposed_action` equivalent in browser content is never passed to `AGI_LC_CAPABILITY_GRANT`.

An accepted action means only that a bounded policy and kernel control-plane contract allowed a structured browser record. It does not mean that navigation succeeded, page content is safe, an upload was appropriate, a download is trusted, or an external tool result is correct.

## Prompt-injection review

The fixture rejects instruction-shaped content containing requests to ignore prior instructions, grant capability, reveal secrets, execute privileged operations, or use `sudo`. The rejection happens before `AGI_LC_BROWSER_RECORD`, increments an observable hostile-content count, and leaves the kernel grant and policy unchanged. This is a test of the no-authority boundary, not a claim of universal prompt-injection resistance.

## Lifecycle review

The network policy is applied before browser opening. Browser open, semantic action, query, cancel, and capability/network teardown are explicit. A cancelled browser session is terminal. M75 does not silently reopen a session or widen a policy after denial. `fbt_close()` best-effort cancels active browser state, revokes the network policy, revokes the capability grant, and closes the M71 session.

## Review conclusion

The demonstrated M75 security gates pass for capability-scoped browser control, bounded network policy, transfer-scope checks, operator-confirmation checks, hostile-content rejection, malformed-action rejection, provenance capture, and cancellation. The broker is not a complete browser security architecture and does not remove the need for independent supervisor/operator approval, real browser-engine sandboxing, full filesystem path mediation, URL/destination policy, and broader fuzzing before production deployment.
