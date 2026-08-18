#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--trusted-keys', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--provenance', type=Path, required=True)
    args = p.parse_args()
    package = json.loads(args.package.resolve().read_text())
    keys = json.loads(args.trusted_keys.resolve().read_text()).get('keys', {})
    candidate = json.loads(args.candidate.resolve().read_text())
    provenance = json.loads(args.provenance.resolve().read_text())
    if package.get('schema') != 'org.faisal.external-qualification-intake.v1':
        fail('qualification package schema mismatch')
    payload = package.get('payload')
    if not isinstance(payload, dict):
        fail('qualification payload missing')
    if package.get('payload_sha256') != hashlib.sha256(canonical(payload)).hexdigest():
        fail('qualification payload digest mismatch')
    key = keys.get(payload.get('key_id'))
    if not isinstance(key, dict) or key.get('status') != 'active':
        fail('reviewer key is not active and trusted')
    if key.get('test_only') is True or key.get('project_affiliated') is True:
        fail('test-only or project-affiliated reviewer is prohibited')
    if key.get('reviewer_id') != payload.get('reviewer_id'):
        fail('reviewer identity mismatch')
    if payload.get('independent_of_project') is not True or payload.get('conflict_free') is not True:
        fail('reviewer independence or conflict declaration is incomplete')
    if payload.get('candidate_sha256') != sha(args.candidate.resolve()):
        fail('qualification is bound to a different candidate')
    if payload.get('provenance_sha256') != sha(args.provenance.resolve()):
        fail('qualification is bound to different provenance')
    if payload.get('source_revision') != provenance.get('source_revision'):
        fail('qualification source revision mismatch')
    if payload.get('production_allowed') is not True:
        fail('qualification disposition does not allow production')
    if payload.get('signed_by_reviewer') is not True:
        fail('reviewer signature disposition is absent')
    now = datetime.now(timezone.utc).timestamp()
    if datetime.fromisoformat(payload.get('expires_at', '').replace('Z', '+00:00')).timestamp() <= now:
        fail('qualification package is expired')
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(key['public_key_b64'], validate=True))
        public.verify(base64.b64decode(package['signature_ed25519'], validate=True), canonical(payload))
    except (InvalidSignature, ValueError, KeyError):
        fail('reviewer signature verification failed')
    print('FAISAL_EXTERNAL_QUALIFICATION_INTAKE_OK checks=16')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_EXTERNAL_QUALIFICATION_INTAKE_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
