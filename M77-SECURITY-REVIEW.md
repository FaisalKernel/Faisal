# FAISAL M77 Security Review

## Security scope

M77 is a bounded userspace research/provenance service. It uses the M75 browser/tool broker for scoped acquisition, the FAISAL verified-knowledge interface for kernel-tracked source state, M71 for durable retained content, and M73 for fresh world-state promotion. It does not add network authority, browser authority, or semantic truth authority to the kernel.

## Threat model

A hostile webpage, prompt-injected document, compromised source, malicious model, malformed metadata producer, or compromised userspace service may attempt to become a verified fact, erase a conflict, impersonate a primary source, bypass freshness, or promote content without independent evidence.

| Threat | M77 control | Residual risk |
|---|---|---|
| Page or model text becomes authority | Browser content is data; promotion requires kernel verification state and explicit evidence digest | Semantic interpretation remains a userspace responsibility |
| Broad network access | M75 applies the scoped network policy and browser capability before M77 acquisition | Production policy composition requires deployment review |
| Source spoofing/rank inflation | Source kind, rank, confidence, URI hash, and source ID are explicit bounded fields; source preference is not authority | M77 does not independently authenticate every publisher |
| Content tampering | Source and content SHA-256 digests are retained; kernel integrity-measured flag is used | Digest identity does not prove origin or correctness |
| Unverified claim promotion | `m77_promote_verified` requires verified, fresh, non-conflicting kernel state | A false but consistently cross-checked claim can still pass bounded policy |
| Conflict suppression | Kernel cross-check retains both records and returns conflict state; M77 denies verification and promotion | Future policy may need explicit human-supervisor conflict resolution |
| Freshness bypass | Freshness TTL is bounded by kernel maximum; kernel reports stale/expired state; promotion requires fresh | Publication semantics are source-reported and may be absent or wrong |
| Metadata denial of service | Claim, URI, content, source kind, confidence, rank, and TTL are bounded before kernel publication; 64 malformed cases are tested | Full parser fuzzing for arbitrary HTTP metadata is future work |
| Provenance loss | Browser action/event sequence, M71 record, source/content digests, knowledge record, retrieval state, and evidence sequence are retained | Cross-service distributed provenance still needs a common bundle format |

## Kernel knowledge contract

M77 follows the FAISAL knowledge handler’s explicit separation between publish, query, cross-check, verify, and update operations. Publication starts unverified. Cross-checking distinct source IDs compares retained content digests and marks both records as conflicting when they differ. Verification requires a nonzero evidence digest and is rejected by M77 when a conflict is present. The kernel also tracks retrieval time, freshness, generation, provenance sequence, and evidence sequence.

## World-state boundary

M73 receives a value only after M77 has observed `AGI_LC_KNOWLEDGE_VERIFY_VERIFIED`, no detected conflict, and a fresh state. This is an authorization boundary for the service operation, not proof that the proposition is true. World-state promotion does not grant any action capability.

## Security test conclusion

The M77 negative paths pass for unverified promotion denial, conflicting-source retention, conflict verification denial, metadata fuzz rejection, and scoped browser acquisition. The review supports the claim that M77 enforces the demonstrated bounded policy. It does not support claims of universal source authenticity, semantic truth, complete prompt-injection immunity, or safe autonomous action.
