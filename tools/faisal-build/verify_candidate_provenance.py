#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
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
    p.add_argument('--build-manifest', type=Path, required=True)
    p.add_argument('--sbom', type=Path, required=True)
    args = p.parse_args()
    repo = args.repo.resolve()
    manifest = json.loads(args.build_manifest.resolve().read_text())
    sbom = args.sbom.resolve().read_text()
    git = __import__('subprocess')
    head = git.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    parent = git.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD^'], text=True).strip()
    if manifest.get('schema') != 'org.faisal.current-lts-provenance.v1':
        fail('provenance schema mismatch')
    if manifest.get('repository_head') not in {head, parent}:
        fail('provenance repository HEAD is neither HEAD nor the immediate bookkeeping parent')
    if manifest.get('source_revision') != LTS_SOURCE_REVISION:
        fail('provenance source revision mismatch')
    if manifest.get('signature', {}).get('status') != 'unsigned_local_provenance_only':
        fail('provenance signature boundary overstated')
    if manifest.get('signature', {}).get('independent_builder') is not False:
        fail('independent builder status overstated')
    config = Path(manifest['config']['path'])
    bz = Path(manifest['artifacts']['bzImage']['path'])
    if not config.is_file() or sha(config) != manifest['config']['sha256']:
        fail('config hash mismatch')
    if not bz.is_file() or sha(bz) != manifest['artifacts']['bzImage']['sha256']:
        fail('bzImage hash mismatch')
    if manifest['config'].get('required_CONFIG_CFS_BANDWIDTH') != 'y' or 'CONFIG_CFS_BANDWIDTH=y' not in config.read_text():
        fail('required scheduler configuration missing')
    for token in (LTS_SOURCE_REVISION, manifest['artifacts']['bzImage']['sha256'], manifest['config']['sha256']):
        if token not in sbom:
            fail('SBOM binding missing: ' + token)
    print('FAISAL_CANDIDATE_PROVENANCE_OK')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_CANDIDATE_PROVENANCE_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
