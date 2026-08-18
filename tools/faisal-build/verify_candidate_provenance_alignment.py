#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

LTS_SOURCE_REVISION = '105f2b85e4c26305a79f5e584df6ebb705858d33'

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def fail(message: str) -> None:
    raise ValueError(message)

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--provenance', type=Path, required=True)
    args = p.parse_args()
    repo = args.repo.resolve()
    candidate = json.loads(args.candidate.resolve().read_text())
    provenance = json.loads(args.provenance.resolve().read_text())
    git = subprocess
    head = git.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    def binding_distance(bound: str) -> int:
        result = git.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', bound, head], stdout=git.DEVNULL, stderr=git.DEVNULL)
        if result.returncode != 0:
            return -1
        return int(git.check_output(['git', '-C', str(repo), 'rev-list', '--count', f'{bound}..{head}'], text=True).strip())
    candidate_head = candidate.get('repository_head')
    provenance_head = provenance.get('repository_head')
    if binding_distance(candidate_head or '') not in range(0, 4):
        fail('candidate is outside the bounded metadata window')
    if binding_distance(provenance_head or '') not in range(0, 4):
        fail('provenance is outside the bounded metadata window')
    lineage = git.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', provenance_head or '', candidate_head or ''], stdout=git.DEVNULL, stderr=git.DEVNULL)
    if lineage.returncode != 0:
        fail('provenance and candidate have divergent lineage')
    if candidate.get('lts_source_revision') != provenance.get('source_revision') or candidate.get('lts_source_revision') != LTS_SOURCE_REVISION:
        fail('candidate and provenance source revisions differ')
    artifact = candidate.get('artifact', {})
    p_artifact = provenance.get('artifacts', {}).get('bzImage', {})
    if artifact.get('bzImage_path') != p_artifact.get('path') or artifact.get('bzImage_sha256') != p_artifact.get('sha256'):
        fail('candidate and provenance bzImage bindings differ')
    if not Path(artifact['bzImage_path']).is_file() or sha(Path(artifact['bzImage_path'])) != artifact['bzImage_sha256']:
        fail('candidate bzImage hash is not reproducible from local artifact')
    p_config = provenance.get('config', {})
    if artifact.get('config_path') != p_config.get('path') or artifact.get('config_sha256') != p_config.get('sha256'):
        fail('candidate and provenance config bindings differ')
    config = Path(artifact['config_path'])
    if not config.is_file() or sha(config) != artifact['config_sha256']:
        fail('candidate config hash is not reproducible from local artifact')
    if artifact.get('required_config', {}).get('CONFIG_CFS_BANDWIDTH') != p_config.get('required_CONFIG_CFS_BANDWIDTH') or p_config.get('required_CONFIG_CFS_BANDWIDTH') != 'y':
        fail('required scheduler configuration binding differs')
    if provenance.get('signature', {}).get('independent_builder') is not False or provenance.get('signature', {}).get('operator_approved') is not False:
        fail('provenance authority boundary is overstated')
    print('FAISAL_CANDIDATE_PROVENANCE_ALIGNMENT_OK checks=11 head=' + head)

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_CANDIDATE_PROVENANCE_ALIGNMENT_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
