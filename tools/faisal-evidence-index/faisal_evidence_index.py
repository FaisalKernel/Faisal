#!/usr/bin/env python3
"""Deterministic, fail-closed release-evidence snapshot exporter for FAISAL."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "org.faisal.release-evidence-index.v1"
REQUIRED_BOUNDARIES = (
    "model_output_is_authority",
    "evidence_receipt_is_production_authority",
    "production_approval",
)


class EvidenceIndexError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceIndexError(message)


def relative_path(value: str) -> Path:
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts, "evidence path must be repository relative")
    return path


@dataclass(frozen=True)
class EvidenceIndexPolicy:
    release_tag: str
    release_head: str
    artifact_digest: str
    issued_at: int
    expires_at: int
    required_external_categories: tuple[str, ...]

    def __post_init__(self) -> None:
        require(bool(self.release_tag), "release tag required")
        require(len(self.release_head) == 40, "release head must be 40 characters")
        require(self.artifact_digest.startswith("sha256:") and len(self.artifact_digest) == 71, "artifact digest required")
        require(self.issued_at < self.expires_at, "invalid policy lifecycle")
        require(len(self.required_external_categories) >= 1, "external categories required")


def derive_category(path: str) -> str:
    lowered = path.lower()
    if "signing" in lowered:
        return "operator_signing"
    if "hardware" in lowered:
        return "physical_hardware"
    if "security" in lowered:
        return "external_security_review"
    if "multihost" in lowered or "replication" in lowered:
        return "live_multihost"
    return "local_control_plane"


def safe_bool(value: Any) -> bool:
    return value is True


def load_evidence(repo: Path, manifest: dict[str, Any], policy: EvidenceIndexPolicy) -> list[dict[str, Any]]:
    require(manifest.get("repository_head") == policy.release_head, "candidate manifest head mismatch")
    require(manifest.get("artifact", {}).get("bzImage_sha256") == policy.artifact_digest.removeprefix("sha256:"), "candidate artifact mismatch")
    rows: list[dict[str, Any]] = []
    for entry in manifest.get("evidence_index", []):
        path_text = entry.get("path")
        expected = entry.get("sha256")
        require(isinstance(path_text, str) and isinstance(expected, str) and len(expected) == 64, "invalid evidence manifest entry")
        path = repo / relative_path(path_text)
        require(path.is_file(), f"missing evidence file: {path_text}")
        actual = file_digest(path)
        require(actual == expected, f"evidence digest mismatch: {path_text}")
        parsed = json.loads(path.read_text())
        boundary = parsed.get("boundary", {})
        security = parsed.get("security_boundaries", {})
        production_claim = safe_bool(boundary.get("production_approval")) or safe_bool(security.get("production_approval"))
        require(not production_claim, f"evidence file asserts production approval: {path_text}")
        rows.append({
            "path": path_text,
            "sha256": actual,
            "record_digest": parsed.get("record_digest", "unbound"),
            "category": derive_category(path_text),
            "boundary_present": isinstance(boundary, dict),
            "production_approval": False,
            "external_evidence_verified": False,
        })
    require(len(rows) > 0, "no evidence listed")
    return sorted(rows, key=lambda row: row["path"])


def build_snapshot(repo: Path, manifest: dict[str, Any], policy: EvidenceIndexPolicy, now: int) -> dict[str, Any]:
    require(policy.issued_at <= now <= policy.expires_at, "policy expired")
    evidence = load_evidence(repo, manifest, policy)
    indexed_categories = {row["category"] for row in evidence}
    missing_external = sorted(set(policy.required_external_categories) - indexed_categories)
    state = {
        "local_index_verified": True,
        "external_evidence_verified": False,
        "production_ready": False,
        "production_approval": False,
        "model_output_is_authority": False,
        "evidence_receipt_is_production_authority": False,
    }
    snapshot = {
        "schema": SCHEMA,
        "release": {
            "tag": policy.release_tag,
            "head": policy.release_head,
            "artifact_digest": policy.artifact_digest,
            "candidate_manifest_digest": digest(manifest),
        },
        "policy": {
            "issued_at": policy.issued_at,
            "expires_at": policy.expires_at,
            "required_external_categories": list(policy.required_external_categories),
        },
        "evidence": evidence,
        "state": state,
        "missing_external_categories": missing_external,
        "release_blockers": list(manifest.get("release_blockers", [])),
        "generated_at": now,
    }
    snapshot["snapshot_digest"] = digest(snapshot)
    return snapshot


def verify_snapshot(snapshot: dict[str, Any], policy: EvidenceIndexPolicy, now: int) -> bool:
    require(snapshot.get("schema") == SCHEMA, "unexpected snapshot schema")
    require(snapshot.get("release", {}).get("tag") == policy.release_tag, "snapshot tag mismatch")
    require(snapshot.get("release", {}).get("head") == policy.release_head, "snapshot head mismatch")
    require(snapshot.get("release", {}).get("artifact_digest") == policy.artifact_digest, "snapshot artifact mismatch")
    state = snapshot.get("state", {})
    require(all(state.get(key) is False for key in REQUIRED_BOUNDARIES), "authority boundary violation")
    require(state.get("production_ready") is False, "production state must remain false")
    require(snapshot.get("generated_at", 0) <= now <= policy.expires_at, "snapshot expired")
    candidate = dict(snapshot)
    actual = candidate.pop("snapshot_digest", None)
    require(actual == digest(candidate), "snapshot digest mismatch")
    return True


class EvidenceIndexLedger:
    def __init__(self, policy: EvidenceIndexPolicy):
        self.policy = policy
        self._nonces: set[str] = set()
        self._digests: set[str] = set()

    def record(self, snapshot: dict[str, Any], nonce: str, sequence: int, now: int, authority: dict[str, bool]) -> dict[str, Any]:
        require(sequence == len(self._digests) + 1, "sequence gap")
        require(bool(nonce) and nonce not in self._nonces, "replayed nonce")
        require(all(authority.get(key) is False for key in REQUIRED_BOUNDARIES), "authority boundary violation")
        verify_snapshot(snapshot, self.policy, now)
        item_digest = snapshot["snapshot_digest"]
        require(item_digest not in self._digests, "replayed snapshot")
        self._nonces.add(nonce)
        self._digests.add(item_digest)
        return {"sequence": sequence, "nonce": nonce, "snapshot_digest": item_digest, "receipt_digest": digest({"sequence": sequence, "nonce": nonce, "snapshot_digest": item_digest})}
