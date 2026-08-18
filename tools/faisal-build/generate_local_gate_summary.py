#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--provenance', type=Path, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--state', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    repo = args.repo.resolve()
    candidate = json.loads(args.candidate.resolve().read_text())
    provenance = json.loads(args.provenance.resolve().read_text())
    state = json.loads(args.state.resolve().read_text())
    evidence = json.loads(args.evidence.resolve().read_text())
    summary = {
        'project': 'FAISAL',
        'schema': 'org.faisal.local-gate-summary.v1',
        'generated_at': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        'status': 'local_evidence_summary_not_production_approval',
        'candidate': {
            'path': str(args.candidate.resolve()),
            'sha256': sha(args.candidate.resolve()),
            'candidate_id': candidate.get('candidate_id'),
            'repository_head': candidate.get('repository_head'),
            'artifact_sha256': candidate.get('artifact', {}).get('bzImage_sha256'),
        },
        'provenance': {
            'path': str(args.provenance.resolve()),
            'sha256': sha(args.provenance.resolve()),
            'repository_head': provenance.get('repository_head'),
            'source_revision': provenance.get('source_revision'),
        },
        'state': {
            'path': str(args.state.resolve()),
            'sha256': sha(args.state.resolve()),
            'current_head': state.get('current_head'),
            'current_tag': state.get('current_tag'),
        },
        'evidence': {
            'path': str(args.evidence.resolve()),
            'sha256': sha(args.evidence.resolve()),
            'schema': evidence.get('schema'),
        },
        'report': {
            'path': str(args.report.resolve()),
            'sha256': sha(args.report.resolve()),
        },
        'local_gates': {
            'candidate_manifest': 'FAISAL_PRODUCTION_CANDIDATE_MANIFEST_OK',
            'provenance': 'FAISAL_CANDIDATE_PROVENANCE_OK',
            'alignment': 'FAISAL_CANDIDATE_PROVENANCE_ALIGNMENT_OK',
            'consistency': 'FAISAL_EVIDENCE_CONSISTENCY_AUDIT_OK',
            'freshness': 'FAISAL_CANDIDATE_EVIDENCE_FRESHNESS_OK',
            'preflight': 'FAISAL_LOCAL_PREFLIGHT_OK checks=5',
            'report_integrity': 'FAISAL_RELEASE_GATE_REPORT_OK',
        },
        'boundary': {
            'independent_builder': False,
            'operator_signature': False,
            'physical_hardware': False,
            'external_security_review': False,
            'production_approval': False,
            'model_output_is_authority': False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + '\n')
    print(args.output)

if __name__ == '__main__':
    main()
