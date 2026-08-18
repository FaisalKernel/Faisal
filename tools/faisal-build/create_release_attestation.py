#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--provenance', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--private-key-b64', required=True)
    parser.add_argument('--key-id', required=True)
    parser.add_argument('--operator-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--disposition', choices=['blocked', 'approved'], default='blocked')
    parser.add_argument('--test-only', action='store_true')
    parser.add_argument('--external-evidence-complete', action='store_true')
    args = parser.parse_args()

    candidate = json.loads(args.candidate.resolve().read_text())
    provenance = json.loads(args.provenance.resolve().read_text())
    bundle = args.bundle.resolve()
    bundle_manifest = json.loads((bundle / 'bundle.json').read_text())
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        'schema': 'org.faisal.release-attestation-payload.v1',
        'key_id': args.key_id,
        'operator_id': args.operator_id,
        'issued_at': now.isoformat().replace('+00:00', 'Z'),
        'expires_at': (now + timedelta(hours=1)).isoformat().replace('+00:00', 'Z'),
        'candidate_sha256': sha(args.candidate.resolve()),
        'provenance_sha256': sha(args.provenance.resolve()),
        'bundle_manifest_sha256': sha(bundle / 'bundle.json'),
        'repository_head': candidate.get('repository_head'),
        'source_revision': provenance.get('source_revision'),
        'current_tag': bundle_manifest.get('current_tag'),
        'disposition': args.disposition,
        'test_only': bool(args.test_only),
        'external_evidence_complete': bool(args.external_evidence_complete),
        'model_output_is_authority': False,
    }
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(args.private_key_b64, validate=True))
    signature = private_key.sign(canonical(payload))
    attestation = {
        'schema': 'org.faisal.release-attestation.v1',
        'signed_payload_sha256': hashlib.sha256(canonical(payload)).hexdigest(),
        'payload': payload,
        'signature_ed25519': base64.b64encode(signature).decode(),
    }
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(attestation, indent=2, sort_keys=True) + '\n')
    print(args.output.resolve())


if __name__ == '__main__':
    main()
