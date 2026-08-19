#!/usr/bin/env python3
"""Fail-closed independent external security-review evidence contract."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any

SCHEMA = "org.faisal.independent-security-review.v1"
REQUIRED_CONTROLS = ("threat_model", "secure_build", "uapi_security", "isolation", "supply_chain", "incident_response", "release_governance")
REQUIRED_METHODS = ("architecture_review", "source_review", "dependency_review", "adversarial_testing", "configuration_review", "findings_retest")
AUTHORITY_KEYS = ("model_output_is_authority", "reviewer_claim_is_authority", "report_receipt_is_production_authority", "production_approval")
EXTERNAL_ORIGINS = {"external_reference", "independent_assessment"}


class SecurityReviewError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SecurityReviewError(message)


def sha_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71


@dataclass(frozen=True)
class ReviewPolicy:
    review_id: str
    release_tag: str
    release_head: str
    artifact_digest: str
    scope_id: str
    methodology_id: str
    required_controls: tuple[str, ...]
    required_methods: tuple[str, ...]
    generation: int
    issued_at: int
    expires_at: int
    trusted_registry_id: str

    def __post_init__(self) -> None:
        require(bool(self.review_id) and bool(self.release_tag) and bool(self.scope_id), "review identity and scope required")
        require(isinstance(self.release_head, str) and len(self.release_head) == 40, "release_head must be full hash")
        require(sha_ref(self.artifact_digest), "artifact_digest must be sha256 reference")
        require(set(self.required_controls) == set(REQUIRED_CONTROLS), "required control set incomplete")
        require(set(self.required_methods) == set(REQUIRED_METHODS), "required method set incomplete")
        require(bool(self.methodology_id) and self.generation >= 1 and self.issued_at < self.expires_at, "invalid policy lifecycle")
        require(bool(self.trusted_registry_id), "trusted reviewer registry reference required")


@dataclass(frozen=True)
class ReviewEvidence:
    evidence_id: str
    origin: str
    release_tag: str
    release_head: str
    artifact_digest: str
    scope_id: str
    methodology_id: str
    assessor_id: str
    assessor_organization: str
    independence_statement: str
    conflict_of_interest_statement: str
    accreditation_reference: str
    control_coverage: dict[str, str]
    method_coverage: dict[str, str]
    evidence_index_digest: str
    findings_digest: str
    remediation_digest: str
    residual_risk_digest: str
    report_digest: str
    reviewer_signature_digest: str
    verification_reference: str
    observed_at: int
    expires_at: int
    nonce: str
    synthetic_fixture: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReviewLedger:
    def __init__(self, policy: ReviewPolicy):
        self.policy = policy
        self._records: dict[str, ReviewEvidence] = {}
        self._nonces: set[str] = set()
        self._digests: set[str] = set()

    def _validate(self, evidence: ReviewEvidence, now: int) -> None:
        p = self.policy
        require(evidence.origin in EXTERNAL_ORIGINS | {"local_preparation", "test_fixture"}, "unsupported review origin")
        require(evidence.release_tag == p.release_tag and evidence.release_head == p.release_head, "release binding mismatch")
        require(evidence.artifact_digest == p.artifact_digest and sha_ref(evidence.artifact_digest), "artifact binding mismatch")
        require(evidence.scope_id == p.scope_id and evidence.methodology_id == p.methodology_id, "scope or methodology mismatch")
        require(bool(evidence.assessor_id) and bool(evidence.assessor_organization), "assessor identity required")
        require(bool(evidence.independence_statement) and bool(evidence.conflict_of_interest_statement), "independence and conflict statements required")
        require(evidence.accreditation_reference.startswith("registry:"), "reviewer registry reference required")
        require(set(evidence.control_coverage) == set(p.required_controls), "control coverage incomplete")
        require(set(evidence.method_coverage) == set(p.required_methods), "method coverage incomplete")
        require(all(value in {"pass", "partial", "fail", "not_run"} for value in evidence.control_coverage.values()), "invalid control coverage")
        require(all(value in {"pass", "partial", "fail", "not_run"} for value in evidence.method_coverage.values()), "invalid method coverage")
        for field in (evidence.evidence_index_digest, evidence.findings_digest, evidence.remediation_digest, evidence.residual_risk_digest, evidence.report_digest, evidence.reviewer_signature_digest):
            require(sha_ref(field), "review evidence digest required")
        require(bool(evidence.verification_reference), "verification reference required")
        require(evidence.observed_at >= p.issued_at and evidence.expires_at <= p.expires_at and now <= evidence.expires_at, "review validity window failure")
        require(bool(evidence.evidence_id) and bool(evidence.nonce), "review ID and nonce required")
        require(evidence.nonce not in self._nonces, "replayed review nonce")
        require(digest(evidence.as_dict()) not in self._digests, "replayed review digest")

    def record(self, evidence: ReviewEvidence, sequence: int, nonce: str, now: int, authority: dict[str, bool]) -> dict[str, Any]:
        require(all(authority.get(key) is False for key in AUTHORITY_KEYS), "authority boundary violation")
        require(sequence == len(self._records) + 1, "sequence gap")
        require(nonce == evidence.nonce, "nonce mismatch")
        self._validate(evidence, now)
        self._records[evidence.evidence_id] = evidence
        self._nonces.add(nonce)
        self._digests.add(digest(evidence.as_dict()))
        return {"sequence": sequence, "evidence_id": evidence.evidence_id, "record_digest": digest(evidence.as_dict())}

    def status(self, now: int, authority: dict[str, bool]) -> dict[str, Any]:
        require(all(authority.get(key) is False for key in AUTHORITY_KEYS), "authority boundary violation")
        records = list(self._records.values())
        complete = len(records) == 1 and set(records[0].control_coverage) == set(self.policy.required_controls) and set(records[0].method_coverage) == set(self.policy.required_methods) and all(value == "pass" for value in records[0].control_coverage.values()) and all(value == "pass" for value in records[0].method_coverage.values())
        external = complete and records[0].origin in EXTERNAL_ORIGINS if records else False
        blockers: list[str] = []
        if not complete: blockers.append("complete_review_evidence")
        if not external: blockers.append("independent_external_assessment")
        blockers.append("reviewer_identity_and_independence_verification")
        blockers.append("signed_findings_disposition_and_retest")
        blockers.append("production_authority_not_issued")
        return {
            "review_records": len(records),
            "structurally_complete": complete,
            "external_review_evidence_structurally_complete": external,
            "independent_external_review_completed": False,
            "reviewer_identity_verified": False,
            "findings_disposition_verified": False,
            "production_approval": False,
            "model_output_is_authority": False,
            "reviewer_claim_is_authority": False,
            "report_receipt_is_production_authority": False,
            "blockers": sorted(set(blockers)),
            "evaluated_at": now,
        }


def local_preparation_status(policy: ReviewPolicy, now: int) -> dict[str, Any]:
    record = ReviewEvidence(
        evidence_id="local-preparation-review", origin="local_preparation", release_tag=policy.release_tag, release_head=policy.release_head, artifact_digest=policy.artifact_digest,
        scope_id=policy.scope_id, methodology_id=policy.methodology_id, assessor_id="local-preparation", assessor_organization="FAISAL-local",
        independence_statement="local preparation is not independent external review", conflict_of_interest_statement="not independently assessed", accreditation_reference="registry:unverified",
        control_coverage={control: "pass" for control in policy.required_controls}, method_coverage={method: "pass" for method in policy.required_methods},
        evidence_index_digest=digest({"index": "local"}), findings_digest=digest({"findings": "local"}), remediation_digest=digest({"remediation": "local"}), residual_risk_digest=digest({"risk": "local"}), report_digest=digest({"report": "local"}), reviewer_signature_digest=digest({"signature": "not-created"}), verification_reference="local-preparation-only", observed_at=policy.issued_at, expires_at=policy.expires_at, nonce="local-preparation-review", synthetic_fixture=True,
    )
    ledger = ReviewLedger(policy)
    ledger.record(record, 1, record.nonce, now, {key: False for key in AUTHORITY_KEYS})
    result = ledger.status(now, {key: False for key in AUTHORITY_KEYS})
    result["local_preparation"] = True
    return result
