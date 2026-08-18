#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    head = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    tag = subprocess.check_output(['git', '-C', str(repo), 'describe', '--tags', '--exact-match', 'HEAD'], text=True).strip()
    names = subprocess.check_output(['git', '-C', str(repo), 'ls-files'], text=True).splitlines()
    include = [name for name in names if not name.startswith('tools/perf/')]
    files = []
    relationships = []
    for index, name in enumerate(include, start=1):
        path = repo / name
        if not path.is_file():
            continue
        file_id = f'SPDXRef-File-{index:06d}'
        files.append({
            'SPDXID': file_id,
            'fileName': name,
            'checksums': [{'algorithm': 'SHA256', 'checksumValue': sha256(path)}],
            'licenseConcluded': 'NOASSERTION',
            'copyrightText': 'NOASSERTION',
        })
        relationships.append({
            'spdxElementId': 'SPDXRef-Package-FAISAL',
            'relationshipType': 'CONTAINS',
            'relatedSpdxElement': file_id,
        })
    document = {
        'spdxVersion': 'SPDX-2.3',
        'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT',
        'name': f'FAISAL source and AI-platform SBOM {tag}',
        'documentNamespace': f'https://faisal.invalid/spdx/{head}',
        'creationInfo': {
            'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'creators': ['Tool: FAISAL generate_faisal_sbom.py'],
        },
        'packages': [{
            'SPDXID': 'SPDXRef-Package-FAISAL',
            'name': 'FAISAL',
            'versionInfo': tag,
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': True,
            'licenseConcluded': 'NOASSERTION',
            'licenseDeclared': 'NOASSERTION',
            'copyrightText': 'NOASSERTION',
            'supplier': 'NOASSERTION',
            'externalRefs': [{
                'referenceCategory': 'OTHER',
                'referenceType': 'faisal.repository.commit',
                'referenceLocator': head,
            }],
        }],
        'files': files,
        'relationships': relationships,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
    print(f'FAISAL_SPDX_SBOM_READY files={len(files)} head={head} output={args.output}')


if __name__ == '__main__':
    main()
