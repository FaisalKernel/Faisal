#!/usr/bin/env python3
"""Fail-closed live multihost qualification evidence contract."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any

SCHEMA = "org.faisal.live-multihost-qualification.v1"
NODE_ORIGINS = {"live_external", "reachable_observation", "synthetic_fixture", "local_single_host"}
EXTERNAL_ORIGINS = {"live_external"}
REQUIRED_WORKLOADS = ("agent_coordination", "distributed_inference", "checkpoint_recovery", "migration_rollback")
REQUIRED_FAULTS = ("node_loss", "network_partition", "transport_reconnect", "workload_restart")
REQUIRED_BOUNDARIES = ("model_output_is_authority", "node_claim_is_authority", "transport_receipt_is_production_authority", "production_approval")


class MultihostQualificationError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MultihostQualificationError(message)


def sha_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71


@dataclass(frozen=True)
class MultihostPolicy:
    qualification_id: str
    release_tag: str
    release_head: str
    artifact_digest: str
    topology_id: str
    required_nodes: int
    quorum: int
    required_workloads: tuple[str, ...]
    required_faults: tuple[str, ...]
    transport_id: str
    generation: int
    issued_at: int
    expires_at: int
    trusted_cluster_registry: str

    def __post_init__(self) -> None:
        require(bool(self.qualification_id) and bool(self.release_tag) and bool(self.topology_id), "qualification identity required")
        require(isinstance(self.release_head, str) and len(self.release_head) == 40, "release_head must be full hash")
        require(sha_ref(self.artifact_digest), "artifact digest required")
        require(self.required_nodes >= 3 and 1 < self.quorum <= self.required_nodes, "multihost quorum policy invalid")
        require(set(self.required_workloads) == set(REQUIRED_WORKLOADS), "workload coverage incomplete")
        require(set(self.required_faults) == set(REQUIRED_FAULTS), "fault coverage incomplete")
        require(bool(self.transport_id) and self.generation >= 1 and self.issued_at < self.expires_at, "invalid transport or policy lifecycle")
        require(bool(self.trusted_cluster_registry), "trusted cluster registry required")


@dataclass(frozen=True)
class MultihostEvidence:
    evidence_id: str
    origin: str
    release_tag: str
    release_head: str
    artifact_digest: str
    topology_id: str
    transport_id: str
    node_records: tuple[dict[str, str], ...]
    workload_results: dict[str, str]
    fault_results: dict[str, str]
    quorum_observed: int
    transport_evidence_digest: str
    workload_trace_digest: str
    output_digest: str
    checkpoint_digest: str
    recovery_digest: str
    migration_digest: str
    cluster_report_digest: str
    verification_reference: str
    observed_at: int
    expires_at: int
    nonce: str
    synthetic_fixture: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class MultihostLedger:
    def __init__(self, policy: MultihostPolicy):
        self.policy = policy
        self._records: dict[str, MultihostEvidence] = {}
        self._nonces: set[str] = set()
        self._digests: set[str] = set()

    def _validate(self, evidence: MultihostEvidence, now: int) -> None:
        p = self.policy
        require(evidence.origin in NODE_ORIGINS, "unsupported multihost origin")
        require(evidence.release_tag == p.release_tag and evidence.release_head == p.release_head, "release binding mismatch")
        require(evidence.artifact_digest == p.artifact_digest and sha_ref(evidence.artifact_digest), "artifact binding mismatch")
        require(evidence.topology_id == p.topology_id and evidence.transport_id == p.transport_id, "topology or transport mismatch")
        require(len(evidence.node_records) == p.required_nodes, "required node count not met")
        node_ids = [item.get("node_id", "") for item in evidence.node_records]
        require(all(node_ids) and len(set(node_ids)) == len(node_ids), "node identity set invalid")
        for node in evidence.node_records:
            require(node.get("endpoint_reference"), "node endpoint reference required")
            require(node.get("identity_digest") and sha_ref(node["identity_digest"]), "node identity digest required")
            require(node.get("kernel_digest") and sha_ref(node["kernel_digest"]), "node kernel digest required")
            require(node.get("artifact_digest") == p.artifact_digest, "node artifact binding mismatch")
            require(node.get("transport_identity"), "node transport identity required")
            require(node.get("clock_state") in {"synchronized", "unknown"}, "invalid node clock state")
        require(set(evidence.workload_results) == set(p.required_workloads), "workload coverage incomplete")
        require(set(evidence.fault_results) == set(p.required_faults), "fault coverage incomplete")
        require(all(value in {"pass", "fail", "not_run"} for value in evidence.workload_results.values()), "invalid workload result")
        require(all(value in {"pass", "fail", "not_run"} for value in evidence.fault_results.values()), "invalid fault result")
        require(p.quorum <= evidence.quorum_observed <= len(evidence.node_records), "observed quorum invalid")
        for field in (evidence.transport_evidence_digest, evidence.workload_trace_digest, evidence.output_digest, evidence.checkpoint_digest, evidence.recovery_digest, evidence.migration_digest, evidence.cluster_report_digest):
            require(sha_ref(field), "multihost evidence digest required")
        require(bool(evidence.verification_reference) and bool(evidence.evidence_id) and bool(evidence.nonce), "verification reference and identity required")
        require(evidence.observed_at >= p.issued_at and evidence.expires_at <= p.expires_at and now <= evidence.expires_at, "multihost evidence validity failure")
        require(evidence.nonce not in self._nonces, "replayed multihost nonce")
        require(digest(evidence.as_dict()) not in self._digests, "replayed multihost evidence")

    def record(self, evidence: MultihostEvidence, sequence: int, nonce: str, now: int, authority: dict[str, bool]) -> dict[str, Any]:
        require(all(authority.get(key) is False for key in REQUIRED_BOUNDARIES), "authority boundary violation")
        require(sequence == len(self._records) + 1, "sequence gap")
        require(nonce == evidence.nonce, "nonce mismatch")
        self._validate(evidence, now)
        self._records[evidence.evidence_id] = evidence
        self._nonces.add(nonce)
        self._digests.add(digest(evidence.as_dict()))
        return {"sequence": sequence, "evidence_id": evidence.evidence_id, "record_digest": digest(evidence.as_dict())}

    def status(self, now: int, authority: dict[str, bool]) -> dict[str, Any]:
        require(all(authority.get(key) is False for key in REQUIRED_BOUNDARIES), "authority boundary violation")
        records = list(self._records.values())
        record = records[0] if len(records) == 1 else None
        structural = bool(record and all(value == "pass" for value in record.workload_results.values()) and all(value == "pass" for value in record.fault_results.values()) and record.quorum_observed >= self.policy.quorum)
        external = structural and record.origin in EXTERNAL_ORIGINS if record else False
        blockers: list[str] = []
        if not structural: blockers.append("complete_multihost_workload_and_fault_evidence")
        if not external: blockers.append("live_external_multihost_execution")
        blockers.extend(("node_identity_attestation", "transport_and_quorum_verification", "production_authority_not_issued"))
        return {
            "records": len(records),
            "required_nodes": self.policy.required_nodes,
            "quorum": self.policy.quorum,
            "structurally_complete": structural,
            "external_multihost_evidence_structurally_complete": external,
            "live_multihost_qualification_completed": False,
            "node_identity_attested": False,
            "transport_cryptographically_verified": False,
            "distributed_workloads_executed_live": False,
            "fault_recovery_verified": False,
            "migration_rollback_verified": False,
            "production_approval": False,
            "model_output_is_authority": False,
            "node_claim_is_authority": False,
            "transport_receipt_is_production_authority": False,
            "blockers": sorted(set(blockers)),
            "evaluated_at": now,
        }


def local_single_host_status(policy: MultihostPolicy, now: int) -> dict[str, Any]:
    node = {"node_id": "local-only", "endpoint_reference": "loopback-only", "identity_digest": digest({"node": "local-only"}), "kernel_digest": digest({"kernel": policy.release_head}), "artifact_digest": policy.artifact_digest, "transport_identity": "loopback-not-cluster-transport", "clock_state": "unknown"}
    item = MultihostEvidence(
        evidence_id="local-single-host", origin="local_single_host", release_tag=policy.release_tag, release_head=policy.release_head, artifact_digest=policy.artifact_digest, topology_id=policy.topology_id, transport_id=policy.transport_id, node_records=(node,), workload_results={key: "not_run" for key in policy.required_workloads}, fault_results={key: "not_run" for key in policy.required_faults}, quorum_observed=1, transport_evidence_digest=digest({"transport": "loopback"}), workload_trace_digest=digest({"workload": "not-run"}), output_digest=digest({"output": "not-run"}), checkpoint_digest=digest({"checkpoint": "not-run"}), recovery_digest=digest({"recovery": "not-run"}), migration_digest=digest({"migration": "not-run"}), cluster_report_digest=digest({"report": "local"}), verification_reference="local-only", observed_at=policy.issued_at, expires_at=policy.expires_at, nonce="local-single-host", synthetic_fixture=True,
    )
    ledger = MultihostLedger(policy)
    try: ledger.record(item, 1, item.nonce, now, {key: False for key in REQUIRED_BOUNDARIES})
    except MultihostQualificationError: pass
    return {"origin": "local_single_host", "live_multihost_qualification_completed": False, "external_multihost_evidence_structurally_complete": False, "production_approval": False, "observed_nodes": 1, "required_nodes": policy.required_nodes, "blockers": ["live_external_multihost_execution", "required_node_count", "transport_and_quorum_verification", "production_authority_not_issued"]}
