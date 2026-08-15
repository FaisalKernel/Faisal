# FAISAL M74 Security Review

## Security scope

M74 is a bounded userspace orchestration and policy-supervisor service above FAISAL ABI 37. It receives model/runtime requests and outputs, applies a deterministic admission fixture, and uses existing FAISAL session, budget, gate, checkpoint, verification, handoff, recovery, and M71 memory contracts. It does not place model execution or semantic policy inside the kernel.

## Threat model

The model, runtime adapter, prompt content, external data, and proposed action metadata are untrusted. A compromised component may attempt to obtain resources without approval, turn output text into authorization, bypass a checkpoint digest, restore an unverified state, exceed policy ceilings, or exploit malformed request fields.

| Threat | M74 control | Residual risk |
|---|---|---|
| Model output becomes privileged action | Output is only digested and stored as a proposal; no capability-grant or tool-action ioctl is called | Future tool brokers must preserve the same boundary |
| Missing or forged approval | Admission requires separate supervisor and operator approval bits with distinct nonces | The fixture is not a production identity/attestation service |
| Resource exhaustion | CPU and memory requests are bounded by policy and enforced by FAISAL budget ioctls | Policy ceiling selection needs workload-specific production review |
| Checkpoint substitution | Kernel returns checkpoint sequence; manifest and verification match state digest and sequence before handoff | Arbitrary accelerator/model device state is not covered without manifest support |
| Rollback to tampered state | Recovery requires matching checkpoint sequence, parent sequence, user-state digest, manifest digest, lineage, and kernel verification state | Userspace model state must be independently restored and validated |
| Malformed policy input | 128 reserved-field mutations and explicit empty-identity, unsupported-workload, duplicate-nonce, missing-approval, and over-budget tests are rejected | Full property-based coverage of every byte remains future work |
| Capability leakage | M71 record capabilities remain scoped to the service session; output action masks are never treated as capabilities | Service compromise still requires kernel/session hardening and independent supervisor isolation |
| Journal poisoning | Model and admission content are digested with OpenSSL EVP and linked to checkpoint sequence provenance | Semantic truth is not established by a digest |
| Approval replay | Distinct nonces are required within each request, and policy generation is recorded with the run | Long-term nonce replay prevention belongs to a production approval service |

## Authority boundary

The kernel remains the enforcing authority for identity, lineage, budgets, gate state, checkpoint integrity, verification, and recovery. The userspace policy fixture decides whether a request meets explicit test-policy conditions; it does not create kernel capabilities. The model output may contain a proposal such as `proposed:delete-file`, but that text is never parsed into a privileged operation. The selftest retains a nonzero proposed action mask solely to demonstrate that the field remains audit data rather than authority.

A successful admission means that the request passed the deterministic fixture and the kernel control-plane sequence. It does not mean that the model is correct, safe, aligned, or authorized to act. Any future action must pass a separate capability-scoped tool broker, trusted-supervisor policy, and operator approval path.

## Checkpoint and rollback review

M74 closes the FAISAL gate before creating a checkpoint because the kernel rejects checkpoint creation while the gate is open. The service verifies the checkpoint using the returned sequence and exact state digest, creates a manifest with explicit task/resource/userspace scope, and exports only a kernel-validated handoff. Rollback marks the checkpoint crashed, uses exact digest and sequence fields for restore-begin, imports the validated handoff, and requests recovery continuation only after kernel verification remains matched. A digest mismatch is a hard failure; no fallback state is fabricated.

The service deliberately does not claim a complete snapshot of GPU/NPU state or arbitrary model runtime state. Such coverage requires provider-backed resources and an independently validated manifest. M74 therefore records the checkpoint boundary as a control-plane and userspace-handoff contract.

## Review conclusion

The demonstrated M74 security gates pass for independent approval inputs, bounded resource admission, malformed-field rejection, model-output non-authority, checkpoint digest verification, and rollback sequencing. The service is not a production trust authority and does not remove the need for independent supervisor isolation, operator approval, hardware/provider validation, model-runtime hardening, or future fuzzing of all ABI fields.
