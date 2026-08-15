# FAISAL M64 Security Validation

M64 was selected as the next unfinished dependency because provenance binding was still a stub and the scoped capability selftest was uncommitted. This validation covers the completed follow-on implementation on the ABI-37 tree.

The binding path requires current FAISAL lineage, current-agent ownership, an existing same-session provenance action/sequence, exact tensor or compute-context capability, and matching resource generation. It stores only bounded identifiers and generation references. The path does not expose model bytes, physical addresses, browser data, or arbitrary device handles.

| Threat | Result |
|---|---|
| Cross-agent reuse of tensor grant | Rejected by the selftest with a denied capability check. |
| Provenance binding to unauthorized tensor | Requires existing read authorization and matching generation. |
| Provenance binding to unauthorized context | Requires active current-agent context, exact capability, and matching generation. |
| Forged provenance identifier | Lookup must resolve an existing same-session action/sequence. |
| Stale resource generation | Rejected without mutating the target. |
| Binding query by another agent | Rejected by binding owner check. |
| Binding revoke after resource mutation | Target reference is cleared only when the binding ID still matches. |
| Unbounded memory exhaustion | Session binding table is fixed at 64 records. |
| Model output becoming authority | No model or text field enters the grant/binding authorization path. |

The implementation composes with Linux DAC, LSM, namespaces, cgroups, seccomp, and provider security. It does not replace kernel hardening, KASAN/KCSAN/lockdep, fuzzing, or security updates. Production use requires an independent trusted supervisor and operator approval.

No semantic, causal, token-level, model-weight, or hardware-execution provenance claim is made.
