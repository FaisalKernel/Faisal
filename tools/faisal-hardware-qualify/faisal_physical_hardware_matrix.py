#!/usr/bin/env python3
"""Fail-closed physical hardware qualification evidence contract.

This module prepares and evaluates evidence for a required hardware matrix. It
never discovers hardware by assertion, performs vendor certification, verifies
cryptographic signatures, or grants production approval. Host observations and
synthetic/external-reference fixtures can be structurally complete only; real
physical qualification remains an external, independently reviewed activity.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any

SCHEMA = "org.faisal.physical-hardware-matrix.v1"
CAPABILITIES = ("gpu", "npu", "iommu", "dma", "rdma", "cxl", "nvme", "numa", "tpm")
REQUIRED_TESTS = ("enumeration", "isolation", "io_path", "performance", "fault_recovery", "power_thermal")
EXTERNAL_ORIGINS = {"external_reference", "independent_lab_reference"}
AUTHORITY_KEYS = (
    "model_output_is_authority",
    "operator_claim_is_authority",
    "provider_metadata_is_authority",
    "production_approval",
)


class HardwareMatrixError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HardwareMatrixError(message)


def sha_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71


@dataclass(frozen=True)
class MatrixPolicy:
    matrix_id: str
    release_tag: str
    release_head: str
    artifact_digest: str
    required_capabilities: tuple[str, ...]
    required_tests: tuple[str, ...]
    generation: int
    issued_at: int
    expires_at: int
    trusted_observer_id: str

    def __post_init__(self) -> None:
        require(bool(self.matrix_id), "matrix_id required")
        require(bool(self.release_tag), "release_tag required")
        require(isinstance(self.release_head, str) and len(self.release_head) == 40, "release_head must be full hash")
        require(sha_ref(self.artifact_digest), "artifact_digest must be sha256 reference")
        require(len(self.required_capabilities) > 0, "required capabilities required")
        require(set(self.required_capabilities) <= set(CAPABILITIES), "unknown required capability")
        require(len(set(self.required_capabilities)) == len(self.required_capabilities), "duplicate required capability")
        require(set(self.required_tests) == set(REQUIRED_TESTS), "required test set must cover the complete matrix contract")
        require(self.generation >= 1 and self.issued_at < self.expires_at, "invalid generation or validity window")
        require(bool(self.trusted_observer_id), "trusted observer reference required")


@dataclass(frozen=True)
class HardwareEvidence:
    evidence_id: str
    capability: str
    origin: str
    release_tag: str
    release_head: str
    artifact_digest: str
    device_identity: dict[str, str]
    firmware_digest: str
    driver_digest: str
    topology_digest: str
    test_results: dict[str, str]
    benchmark_digest: str
    fault_recovery_digest: str
    external_report_digest: str
    verification_reference: str
    observed_at: int
    expires_at: int
    nonce: str
    synthetic_fixture: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class HardwareMatrixLedger:
    def __init__(self, policy: MatrixPolicy):
        self.policy = policy
        self._records: dict[str, HardwareEvidence] = {}
        self._nonces: set[str] = set()
        self._digests: set[str] = set()

    def _validate(self, evidence: HardwareEvidence, now: int) -> None:
        p = self.policy
        require(evidence.capability in p.required_capabilities, "capability is outside required matrix")
        require(evidence.origin in EXTERNAL_ORIGINS | {"host_observation", "test_fixture"}, "unsupported evidence origin")
        require(evidence.release_tag == p.release_tag and evidence.release_head == p.release_head, "release binding mismatch")
        require(evidence.artifact_digest == p.artifact_digest and sha_ref(evidence.artifact_digest), "artifact binding mismatch")
        require(evidence.observed_at >= p.issued_at and evidence.expires_at <= p.expires_at and now <= evidence.expires_at, "evidence validity window failure")
        require(bool(evidence.evidence_id) and bool(evidence.nonce), "evidence ID and nonce required")
        require(evidence.device_identity.get("model") or evidence.device_identity.get("pci_bdf") or evidence.device_identity.get("serial"), "device identity required")
        for field in (evidence.firmware_digest, evidence.driver_digest, evidence.topology_digest, evidence.benchmark_digest, evidence.fault_recovery_digest, evidence.external_report_digest):
            require(sha_ref(field), "evidence digest reference required")
        require(bool(evidence.verification_reference), "verification reference required")
        require(set(evidence.test_results) == set(p.required_tests), "complete required test set is required")
        require(all(value in {"pass", "fail", "not_run"} for value in evidence.test_results.values()), "invalid test result")
        require(evidence.nonce not in self._nonces, "replayed evidence nonce")
        record_digest = digest(evidence.as_dict())
        require(record_digest not in self._digests, "replayed evidence digest")

    def record(self, evidence: HardwareEvidence, sequence: int, nonce: str, now: int, authority: dict[str, bool]) -> dict[str, Any]:
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
        coverage = {capability: [r for r in records if r.capability == capability] for capability in self.policy.required_capabilities}
        structural = all(len(items) == 1 for items in coverage.values()) and all(all(value == "pass" for value in item.test_results.values()) for item in records)
        external = structural and all(item.origin in EXTERNAL_ORIGINS for item in records)
        blockers = []
        if not structural:
            blockers.append("complete_matrix_evidence")
        if not external:
            blockers.append("external_matrix_evidence")
        blockers.append("independent_physical_execution_and_review")
        blockers.append("production_authority_not_issued")
        return {
            "records": len(records),
            "required_capabilities": list(self.policy.required_capabilities),
            "covered_capabilities": sorted(capability for capability, items in coverage.items() if items),
            "missing_capabilities": sorted(capability for capability, items in coverage.items() if not items),
            "structurally_complete": structural,
            "external_hardware_evidence_structurally_complete": external,
            "physical_qualification_completed": False,
            "production_approval": False,
            "model_output_is_authority": False,
            "operator_claim_is_authority": False,
            "provider_metadata_is_authority": False,
            "hardware_observation_is_qualification": False,
            "blockers": sorted(set(blockers)),
            "evaluated_at": now,
        }


def observation_status(policy: MatrixPolicy, observation: dict[str, Any], now: int) -> dict[str, Any]:
    devices = observation.get("devices", {})
    ledger = HardwareMatrixLedger(policy)
    for sequence, capability in enumerate(policy.required_capabilities, 1):
        item = devices.get(capability, {})
        state = item.get("state", "unknown")
        identity = {"model": f"observed-{capability}"} if state == "present" else {"model": f"unobserved-{capability}"}
        evidence = HardwareEvidence(
            evidence_id=f"host-{capability}", capability=capability, origin="host_observation",
            release_tag=policy.release_tag, release_head=policy.release_head, artifact_digest=policy.artifact_digest,
            device_identity=identity, firmware_digest=digest({"capability": capability, "firmware": "unverified"}),
            driver_digest=digest({"capability": capability, "driver": "unverified"}), topology_digest=digest(item),
            test_results={test: "not_run" for test in policy.required_tests}, benchmark_digest=digest({"capability": capability, "benchmark": "not_run"}),
            fault_recovery_digest=digest({"capability": capability, "recovery": "not_run"}), external_report_digest=digest({"capability": capability, "report": "not_run"}),
            verification_reference="host-observation-only", observed_at=policy.issued_at, expires_at=policy.expires_at, nonce=f"host-{capability}", synthetic_fixture=False,
        )
        ledger.record(evidence, sequence, evidence.nonce, now, {key: False for key in AUTHORITY_KEYS})
    result = ledger.status(now, {key: False for key in AUTHORITY_KEYS})
    result["host_observation_states"] = {capability: devices.get(capability, {}).get("state", "unknown") for capability in policy.required_capabilities}
    result["physical_qualification_completed"] = False
    return result


def write_record(record: dict[str, Any], path: str) -> None:
    body = dict(record)
    body["record_digest"] = digest(body)
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(body, stream, indent=2, sort_keys=True)
        stream.write("\n")
