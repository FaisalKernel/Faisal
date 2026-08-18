#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def fail(message: str) -> None:
    raise ValueError(message)


def parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--attestation', type=Path, required=True)
    parser.add_argument('--trusted-keys', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--provenance', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--require-production-approval', action='store_true')
    args = parser.parse_args()
    repo = args.repo.resolve()
    attestation = json.loads(args.attestation.resolve().read_text())
    keyring = json.loads(args.trusted_keys.resolve().read_text())
    candidate = json.loads(args.candidate.resolve().read_text())
    provenance = json.loads(args.provenance.resolve().read_text())
    bundle_manifest = json.loads((args.bundle.resolve() / 'bundle.json').read_text())

    if attestation.get('schema') != 'org.faisal.release-attestation.v1':
        fail('attestation schema mismatch')
    payload = attestation.get('payload')
    signature_b64 = attestation.get('signature_ed25519')
    if not isinstance(payload, dict) or not isinstance(signature_b64, str):
        fail('attestation payload or signature is missing')
    if attestation.get('signed_payload_sha256') != hashlib.sha256(canonical(payload)).hexdigest():
        fail('signed payload digest mismatch')
    key_id = payload.get('key_id')
    operator_id = payload.get('operator_id')
    trusted = keyring.get('keys', {}).get(key_id)
    if not isinstance(trusted, dict):
        fail('attestation key is not trusted')
    if trusted.get('status') != 'active':
        fail('attestation key is not active')
    if trusted.get('operator_id') != operator_id:
        fail('attestation operator identity mismatch')
    if trusted.get('test_only') is True:
        fail('test-only key cannot authorize release')
    if trusted.get('external_operator') is not True:
        fail('key is not marked for an external operator')
    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted['public_key_b64'], validate=True))
        public_key.verify(base64.b64decode(signature_b64, validate=True), canonical(payload))
    except (ValueError, InvalidSignature, KeyError) as exc:
        fail('Ed25519 signature verification failed')

    now = datetime.now(timezone.utc).timestamp()
    if parse_time(payload.get('expires_at', '')) <= now:
        fail('attestation is expired')
    if parse_time(payload.get('issued_at', '')) > now + 60:
        fail('attestation is issued in the future')
    if payload.get('candidate_sha256') != sha(args.candidate.resolve()):
        fail('candidate hash is not bound')
    if payload.get('provenance_sha256') != sha(args.provenance.resolve()):
        fail('provenance hash is not bound')
    if payload.get('bundle_manifest_sha256') != sha(args.bundle.resolve() / 'bundle.json'):
        fail('bundle hash is not bound')
    if payload.get('repository_head') != candidate.get('repository_head'):
        fail('attestation candidate head mismatch')
    if payload.get('source_revision') != provenance.get('source_revision'):
        fail('attestation source revision mismatch')
    if payload.get('current_tag') != bundle_manifest.get('current_tag'):
        fail('attestation tag mismatch')
    if payload.get('disposition') not in {'blocked', 'approved'}:
        fail('invalid attestation disposition')
    if args.require_production_approval:
        if payload.get('disposition') != 'approved':
            fail('production approval disposition is not approved')
        if payload.get('test_only') is True:
            fail('test-only attestation cannot authorize production')
        if payload.get('external_evidence_complete') is not True:
            fail('external evidence completeness is not proven')
        if payload.get('model_output_is_authority') is not False:
            fail('model output authority boundary is overstated')
    print('FAISAL_RELEASE_ATTESTATION_OK checks=18 disposition=' + payload['disposition'])


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_RELEASE_ATTESTATION_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
