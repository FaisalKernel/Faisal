from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.qualification-intake.v1"
CATEGORIES = ("external_security_review", "hardware", "independent_builder", "multihost", "operator_signing")
MAX_TTL = 31_536_000
MAX_NODES = 4096
MAX_CLAIMS = 4096

class QualificationIntakeError(ValueError):
    pass

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()

def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise QualificationIntakeError(f"{name} is invalid")
    return value

def optional_text(value: Any, name: str, limit: int = 512) -> str:
    if value == "":
        return ""
    return text(value, name, limit)

def sha(value: Any, name: str, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    value = text(value, name, 71)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise QualificationIntakeError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise QualificationIntakeError(f"{name} is not a SHA-256 digest") from exc
    return value

def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise QualificationIntakeError(f"{name} is outside bounds")
    return value

def names(value: Any, name: str, maximum: int = 128, minimum: int = 0) -> tuple[str, ...]:
    if not isinstance(value, tuple) or len(value) < minimum or len(value) > maximum:
        raise QualificationIntakeError(f"{name} is outside bounds")
    result = tuple(text(item, f"{name} item", 256) for item in value)
    if tuple(sorted(set(result))) != result:
        raise QualificationIntakeError(f"{name} must be sorted and unique")
    return result

def authority_boundary(value: Mapping[str, Any]) -> None:
    required = (
        "model_output_is_authority", "evidence_claim_is_authority",
        "qualification_receipt_is_production_authority", "production_approval",
    )
    if not isinstance(value, Mapping) or any(value.get(field) is not False for field in required):
        raise QualificationIntakeError("qualification authority boundary violation")

@dataclass(frozen=True)
class QualificationPolicy:
    policy_id: str
    release_tag: str
    release_head: str
    artifact_digest: str
    generation: int
    issued_at: int
    expires_at: int
    min_builder_attestations: int = 2
    min_multihost_nodes: int = 2
    required_categories: tuple[str, ...] = CATEGORIES

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id"); text(self.release_tag, "release_tag"); text(self.release_head, "release_head", 40)
        if len(self.release_head) != 40:
            raise QualificationIntakeError("release_head must be a full commit hash")
        sha(self.artifact_digest, "artifact_digest")
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.expires_at - self.issued_at > MAX_TTL: raise QualificationIntakeError("policy TTL exceeds bound")
        integer(self.min_builder_attestations, "min_builder_attestations", 2, 32); integer(self.min_multihost_nodes, "min_multihost_nodes", 2, MAX_NODES)
        required = names(self.required_categories, "required_categories", maximum=len(CATEGORIES), minimum=1)
        if required != CATEGORIES: raise QualificationIntakeError("required_categories must equal the canonical production blocker set")

    @property
    def policy_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_id": self.policy_id, "release_tag": self.release_tag, "release_head": self.release_head, "artifact_digest": self.artifact_digest, "generation": self.generation, "issued_at": self.issued_at, "expires_at": self.expires_at, "min_builder_attestations": self.min_builder_attestations, "min_multihost_nodes": self.min_multihost_nodes, "required_categories": self.required_categories})

@dataclass(frozen=True)
class QualificationClaim:
    claim_id: str
    category: str
    origin: str
    release_tag: str
    release_head: str
    artifact_digest: str
    issuer_id: str
    issuer_role: str
    evidence_digest: str
    attestation_digest: str
    issued_at: int
    expires_at: int
    verifier_id: str = ""
    verification_method: str = ""
    builder_id: str = ""
    independence_group: str = ""
    signer_id: str = ""
    transparency_log_entry: str = ""
    trusted_root_id: str = ""
    platform_id: str = ""
    firmware_digest: str = ""
    secure_boot: bool = False
    attestation_reference: str = ""
    qualification_suite_digest: str = ""
    reviewer_id: str = ""
    reviewer_independence_declared: bool = False
    report_digest: str = ""
    method_digest: str = ""
    retest_digest: str = ""
    node_ids: tuple[str, ...] = ()
    topology_digest: str = ""
    test_suite_digest: str = ""
    live_execution: bool = False

    def __post_init__(self) -> None:
        text(self.claim_id, "claim_id"); text(self.category, "category"); text(self.origin, "origin")
        if self.category not in CATEGORIES: raise QualificationIntakeError("unsupported qualification category")
        if self.origin not in {"local", "external_reference"}: raise QualificationIntakeError("unsupported claim origin")
        text(self.release_tag, "release_tag"); text(self.release_head, "release_head", 40)
        if len(self.release_head) != 40: raise QualificationIntakeError("release_head must be a full commit hash")
        sha(self.artifact_digest, "artifact_digest"); text(self.issuer_id, "issuer_id"); text(self.issuer_role, "issuer_role"); sha(self.evidence_digest, "evidence_digest"); sha(self.attestation_digest, "attestation_digest")
        integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.expires_at - self.issued_at > MAX_TTL: raise QualificationIntakeError("claim TTL exceeds bound")
        optional_text(self.verifier_id, "verifier_id"); optional_text(self.verification_method, "verification_method"); optional_text(self.builder_id, "builder_id"); optional_text(self.independence_group, "independence_group"); optional_text(self.signer_id, "signer_id"); optional_text(self.transparency_log_entry, "transparency_log_entry"); optional_text(self.trusted_root_id, "trusted_root_id"); optional_text(self.platform_id, "platform_id"); sha(self.firmware_digest, "firmware_digest", optional=True); optional_text(self.attestation_reference, "attestation_reference"); sha(self.qualification_suite_digest, "qualification_suite_digest", optional=True); optional_text(self.reviewer_id, "reviewer_id"); sha(self.report_digest, "report_digest", optional=True); sha(self.method_digest, "method_digest", optional=True); sha(self.retest_digest, "retest_digest", optional=True); names(self.node_ids, "node_ids", maximum=MAX_NODES); sha(self.topology_digest, "topology_digest", optional=True); sha(self.test_suite_digest, "test_suite_digest", optional=True)
        for name, value in (("secure_boot", self.secure_boot), ("reviewer_independence_declared", self.reviewer_independence_declared), ("live_execution", self.live_execution)):
            if not isinstance(value, bool): raise QualificationIntakeError(f"{name} is invalid")

    @property
    def claim_digest(self) -> str:
        return digest({"schema": SCHEMA, "claim_id": self.claim_id, "category": self.category, "origin": self.origin, "release_tag": self.release_tag, "release_head": self.release_head, "artifact_digest": self.artifact_digest, "issuer_id": self.issuer_id, "issuer_role": self.issuer_role, "evidence_digest": self.evidence_digest, "attestation_digest": self.attestation_digest, "issued_at": self.issued_at, "expires_at": self.expires_at, "verifier_id": self.verifier_id, "verification_method": self.verification_method, "builder_id": self.builder_id, "independence_group": self.independence_group, "signer_id": self.signer_id, "transparency_log_entry": self.transparency_log_entry, "trusted_root_id": self.trusted_root_id, "platform_id": self.platform_id, "firmware_digest": self.firmware_digest, "secure_boot": self.secure_boot, "attestation_reference": self.attestation_reference, "qualification_suite_digest": self.qualification_suite_digest, "reviewer_id": self.reviewer_id, "reviewer_independence_declared": self.reviewer_independence_declared, "report_digest": self.report_digest, "method_digest": self.method_digest, "retest_digest": self.retest_digest, "node_ids": self.node_ids, "topology_digest": self.topology_digest, "test_suite_digest": self.test_suite_digest, "live_execution": self.live_execution})

class QualificationLedger:
    def __init__(self, policy: QualificationPolicy) -> None:
        self.policy = policy
        self._claims: dict[str, QualificationClaim] = {}
        self._nonces: set[str] = set()

    def _common(self, claim: QualificationClaim, *, now: int) -> None:
        if claim.release_tag != self.policy.release_tag or claim.release_head != self.policy.release_head or claim.artifact_digest != self.policy.artifact_digest:
            raise QualificationIntakeError("claim release or artifact binding mismatch")
        if claim.origin == "external_reference" and (not claim.verifier_id or not claim.verification_method):
            raise QualificationIntakeError("external reference lacks verifier identity or method")
        if now < claim.issued_at or now >= claim.expires_at or now < self.policy.issued_at or now >= self.policy.expires_at:
            raise QualificationIntakeError("claim or policy is stale")
        if claim.expires_at > self.policy.expires_at:
            raise QualificationIntakeError("claim exceeds policy expiry")

    def _category(self, claim: QualificationClaim) -> None:
        if claim.category == "independent_builder":
            if not claim.builder_id or not claim.independence_group or not claim.qualification_suite_digest:
                raise QualificationIntakeError("builder claim lacks builder identity, independence group, or build-suite digest")
        elif claim.category == "operator_signing":
            if not claim.signer_id or not claim.transparency_log_entry or not claim.trusted_root_id:
                raise QualificationIntakeError("signing claim lacks signer, transparency entry, or trusted root")
        elif claim.category == "hardware":
            if not claim.platform_id or not claim.firmware_digest or not claim.secure_boot or not claim.attestation_reference or not claim.qualification_suite_digest:
                raise QualificationIntakeError("hardware claim lacks platform, firmware, secure boot, attestation, or suite evidence")
        elif claim.category == "external_security_review":
            if not claim.reviewer_id or not claim.reviewer_independence_declared or not claim.report_digest or not claim.method_digest or not claim.retest_digest:
                raise QualificationIntakeError("security-review claim lacks independent reviewer, report, method, or retest evidence")
        elif claim.category == "multihost":
            if claim.origin != "external_reference" or not claim.live_execution or len(claim.node_ids) < self.policy.min_multihost_nodes or not claim.topology_digest or not claim.test_suite_digest:
                raise QualificationIntakeError("multihost claim lacks live external topology or standardized suite evidence")

    def admit(self, claim: QualificationClaim, *, nonce: str, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        authority_boundary(authority); text(nonce, "nonce"); integer(now, "now", 0, 2**63 - 1)
        if claim.claim_digest in self._claims or nonce in self._nonces: raise QualificationIntakeError("claim or nonce replay")
        if len(self._claims) >= MAX_CLAIMS: raise QualificationIntakeError("qualification ledger capacity exceeded")
        self._common(claim, now=now); self._category(claim)
        self._claims[claim.claim_digest] = claim; self._nonces.add(nonce)
        return {"schema": SCHEMA, "status": "claim_admitted", "claim_digest": claim.claim_digest, "category": claim.category, "origin": claim.origin, "structurally_verified": True, "external_attestation_independently_verified": False, "production_approval": False, "authority": dict(authority)}

    def status(self, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        authority_boundary(authority); integer(now, "now", 0, 2**63 - 1)
        fresh = [claim for claim in self._claims.values() if claim.expires_at > now]
        by_category = {category: [claim for claim in fresh if claim.category == category] for category in CATEGORIES}
        builders = {(claim.builder_id, claim.independence_group) for claim in by_category["independent_builder"] if claim.origin == "external_reference"}
        external = {
            "independent_builder": len(builders) >= self.policy.min_builder_attestations,
            "operator_signing": any(claim.origin == "external_reference" for claim in by_category["operator_signing"]),
            "hardware": any(claim.origin == "external_reference" for claim in by_category["hardware"]),
            "external_security_review": any(claim.origin == "external_reference" for claim in by_category["external_security_review"]),
            "multihost": any(claim.origin == "external_reference" for claim in by_category["multihost"]),
        }
        local = {category: any(claim.origin == "local" for claim in by_category[category]) for category in CATEGORIES}
        blockers = [category for category in CATEGORIES if not external[category]]
        return {"schema": SCHEMA, "status": "blocked" if blockers else "external_evidence_structurally_complete", "local_qualification": all(local.values()), "external_evidence_structurally_complete": all(external.values()), "production_approval": False, "blockers": blockers + ["production_authority_not_issued"], "claims": len(self._claims), "external_categories": external, "local_categories": local, "authority": dict(authority)}

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_digest": self.policy.policy_digest, "claims": sorted(self._claims), "nonces": sorted(self._nonces)})
