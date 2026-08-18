#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()

def fail(message: str) -> None:
    raise ValueError(message)

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--summary', type=Path, required=True)
    args = p.parse_args()
    repo = args.repo.resolve()
    summary_path = args.summary.resolve()
    summary = json.loads(summary_path.read_text())
    if summary.get('schema') != 'org.faisal.local-gate-summary.v1':
        fail('summary schema mismatch')
    if summary.get('status') != 'local_evidence_summary_not_production_approval':
        fail('summary status overstates authority')
    head = git(repo, 'rev-parse', 'HEAD')
    candidate = summary.get('candidate', {})
    provenance = summary.get('provenance', {})
    state = summary.get('state', {})
    report = summary.get('report', {})
    for label, item in [('candidate', candidate), ('provenance', provenance), ('state', state), ('report', report)]:
        path = Path(item.get('path', ''))
        if not path.is_file():
            fail(f'{label} artifact is missing')
        if sha(path) != item.get('sha256'):
            fail(f'{label} artifact hash mismatch')
    if candidate.get('repository_head') != candidate.get('candidate_id', '').rsplit('-', 1)[-1] and not candidate.get('candidate_id', '').endswith(candidate.get('repository_head', '')[:12]):
        fail('candidate identity mismatch')
    if state.get('current_tag') != 'FAISAL-M210-RELEASE-GATE-REPORT-INTEGRITY':
        fail('state tag identity mismatch')
    if state.get('current_head') != candidate.get('repository_head'):
        fail('state and candidate heads differ')
    if provenance.get('source_revision') != '105f2b85e4c26305a79f5e584df6ebb705858d33':
        fail('source revision mismatch')
    gates = summary.get('local_gates', {})
    required = ['candidate_manifest', 'provenance', 'alignment', 'consistency', 'freshness', 'preflight', 'report_integrity']
    if any(not gates.get(name) for name in required):
        fail('local gate summary is incomplete')
    boundary = summary.get('boundary', {})
    for key in ['independent_builder', 'operator_signature', 'physical_hardware', 'external_security_review', 'production_approval', 'model_output_is_authority']:
        if boundary.get(key) is not False:
            fail(f'boundary overstated: {key}')
    print(f'FAISAL_LOCAL_GATE_SUMMARY_OK checks=15 head={head}')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_LOCAL_GATE_SUMMARY_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
