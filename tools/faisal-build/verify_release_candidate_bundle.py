#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


SOURCE_REVISION = '105f2b85e4c26305a79f5e584df6ebb705858d33'


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    bundle = args.bundle.resolve()
    manifest_path = bundle / 'bundle.json'
    if not manifest_path.is_file():
        fail('bundle manifest is missing')
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('schema') != 'org.faisal.release-candidate-bundle.v1':
        fail('bundle schema mismatch')
    if manifest.get('status') != 'bounded_candidate_bundle_not_production_approved':
        fail('bundle status overstates authority')
    current_head = git(repo, 'rev-parse', 'HEAD')
    candidate = json.loads((bundle / 'candidate/production-candidate.json').read_text())
    provenance = json.loads((bundle / 'provenance/FAISAL-build-manifest.json').read_text())
    state = json.loads((bundle / 'state/FAISAL-PROGRAM-STATE.json').read_text())
    summary = json.loads((bundle / 'summary/FAISAL-local-gate-summary.json').read_text())
    if candidate.get('lts_source_revision') != SOURCE_REVISION:
        fail('candidate source revision mismatch')
    if provenance.get('source_revision') != SOURCE_REVISION:
        fail('provenance source revision mismatch')
    if manifest.get('repository_head') != candidate.get('repository_head'):
        fail('bundle and candidate heads differ')
    if manifest.get('current_head') != state.get('current_head'):
        fail('bundle and state heads differ')
    state_head = state.get('current_head')
    if not state_head:
        fail('program state head is missing')
    try:
        git(repo, 'merge-base', '--is-ancestor', state_head, current_head)
    except subprocess.CalledProcessError:
        fail('program state head is not an ancestor of repository HEAD')
    distance = int(git(repo, 'rev-list', '--count', f'{state_head}..{current_head}'))
    if distance > 3:
        fail('program state head exceeds bounded metadata window')
    if git(repo, 'rev-parse', f"{state.get('current_tag')}^{{commit}}") != current_head:
        fail('program state tag does not identify repository HEAD')
    if state.get('current_tag') != manifest.get('current_tag'):
        fail('bundle tag identity mismatch')
    if provenance.get('repository_head') != candidate.get('repository_head'):
        fail('candidate and provenance heads differ')
    if summary.get('candidate', {}).get('sha256') != sha(bundle / 'candidate/production-candidate.json'):
        fail('summary candidate hash does not bind bundled candidate')
    if summary.get('provenance', {}).get('sha256') != sha(bundle / 'provenance/FAISAL-build-manifest.json'):
        fail('summary provenance hash does not bind bundled provenance')
    if summary.get('state', {}).get('sha256') != sha(bundle / 'state/FAISAL-PROGRAM-STATE.json'):
        fail('summary state hash does not bind bundled state')
    if summary.get('report', {}).get('sha256') != sha(bundle / 'report/FAISAL-production-release-gate.tsv'):
        fail('summary report hash does not bind bundled report')

    expected_roles = {'candidate_manifest', 'build_manifest', 'sbom', 'local_gate_summary', 'program_state', 'release_gate_report', 'kernel_image', 'kernel_config'}
    roles: set[str] = set()
    for item in manifest.get('files', []):
        role = item.get('role')
        relative = item.get('path', '')
        path = Path(relative)
        if role in roles:
            fail(f'duplicate bundle role: {role}')
        roles.add(role)
        if not relative or path.is_absolute() or '..' in path.parts or path.as_posix() != relative:
            fail(f'unsafe bundle path: {relative!r}')
        target = bundle / path
        if not target.is_file():
            fail(f'bundle file missing: {relative}')
        if sha(target) != item.get('sha256'):
            fail(f'bundle file hash mismatch: {relative}')
        if target.stat().st_size != item.get('size'):
            fail(f'bundle file size mismatch: {relative}')
    if not expected_roles.issubset(roles):
        fail('bundle role set is incomplete')

    boundary = manifest.get('boundary', {})
    for key in ['independent_builder', 'operator_signature', 'physical_hardware', 'external_security_review', 'production_approval', 'model_output_is_authority']:
        if boundary.get(key) is not False:
            fail(f'bundle boundary overstated: {key}')
    print(f'FAISAL_RELEASE_CANDIDATE_BUNDLE_OK checks=24 head={current_head}')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_RELEASE_CANDIDATE_BUNDLE_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
