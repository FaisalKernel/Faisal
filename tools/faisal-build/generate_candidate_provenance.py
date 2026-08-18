#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

LTS_SOURCE_REVISION = '105f2b85e4c26305a79f5e584df6ebb705858d33'

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    repo = args.repo.resolve()
    build = args.build.resolve()
    out = args.output.resolve()
    bz = build / 'arch/x86/boot/bzImage'
    config = build / '.config'
    if not bz.is_file() or not config.is_file():
        raise SystemExit('required LTS artifact or config is missing')
    head = git(repo, 'rev-parse', 'HEAD')
    source_date_epoch = int(git(repo, 'show', '-s', '--format=%ct', 'HEAD'))
    compiler = subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]
    make = subprocess.check_output(['make', '--version'], text=True).splitlines()[0]
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    manifest = {
        'schema': 'org.faisal.current-lts-provenance.v1',
        'project': 'FAISAL',
        'generated_at': generated,
        'repository_head': head,
        'source_revision': LTS_SOURCE_REVISION,
        'source_description': 'Linux 6.18.44 LTS forward-port candidate source lineage',
        'source_date_epoch': source_date_epoch,
        'compiler': compiler,
        'make': make,
        'config': {'path': str(config), 'sha256': sha(config), 'required_CONFIG_CFS_BANDWIDTH': 'y'},
        'artifacts': {'bzImage': {'path': str(bz), 'sha256': sha(bz)}},
        'signature': {'status': 'unsigned_local_provenance_only', 'independent_builder': False, 'operator_approved': False},
        'limitations': ['This local bundle is not an independent rebuild, external attestation, or production signature.'],
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / 'FAISAL-build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    sbom = '\n'.join([
        'SPDXVersion: SPDX-2.3',
        'DataLicense: CC0-1.0',
        'SPDXID: SPDXRef-DOCUMENT',
        'DocumentName: FAISAL-current-LTS-local-provenance',
        f'DocumentNamespace: https://faisal.invalid/sbom/{head}',
        'Creator: Tool: FAISAL generate_candidate_provenance.py',
        f'Created: {generated}',
        '',
        '##### Packages #####',
        'PackageName: FAISAL-Linux-6.18.44-LTS-candidate',
        'SPDXID: SPDXRef-Package-FAISAL-LTS',
        f'PackageVersion: {LTS_SOURCE_REVISION}',
        'PackageDownloadLocation: NOASSERTION',
        'FilesAnalyzed: false',
        'PackageLicenseConcluded: NOASSERTION',
        'PackageLicenseDeclared: NOASSERTION',
        'PackageCopyrightText: NOASSERTION',
        '',
        '##### Files #####',
        f'FileName: {bz}',
        'SPDXID: SPDXRef-File-bzImage',
        f'FileChecksum: SHA256: {sha(bz)}',
        'LicenseConcluded: NOASSERTION',
        'LicenseInfoInFile: NOASSERTION',
        'FileCopyrightText: NOASSERTION',
        '',
        f'FileName: {config}',
        'SPDXID: SPDXRef-File-config',
        f'FileChecksum: SHA256: {sha(config)}',
        'LicenseConcluded: NOASSERTION',
        'LicenseInfoInFile: NOASSERTION',
        'FileCopyrightText: NOASSERTION',
        '',
        '##### Relationships #####',
        'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-FAISAL-LTS',
        'Relationship: SPDXRef-Package-FAISAL-LTS CONTAINS SPDXRef-File-bzImage',
        'Relationship: SPDXRef-Package-FAISAL-LTS CONTAINS SPDXRef-File-config',
        '',
    ])
    (out / 'FAISAL-SBOM.spdx').write_text(sbom)
    print(out)

if __name__ == '__main__':
    main()
