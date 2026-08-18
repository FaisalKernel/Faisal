#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--root-name', default='faisal-release-candidate')
    args = parser.parse_args()
    repo = args.repo.resolve()
    archive_path = args.archive.resolve()
    if not archive_path.is_file():
        fail('archive is missing')
    with tempfile.TemporaryDirectory(prefix='faisal-m214-archive-') as temp:
        extraction_root = Path(temp)
        with tarfile.open(archive_path, mode='r:gz') as archive:
            members = archive.getmembers()
            if not members:
                fail('archive is empty')
            for member in members:
                name = member.name
                path = Path(name)
                if path.is_absolute() or '..' in path.parts or path.as_posix() != name:
                    fail(f'unsafe archive member: {name!r}')
                if not name.startswith(args.root_name + '/'):
                    fail(f'archive member outside fixed root: {name!r}')
                if member.issym() or member.islnk() or not member.isfile():
                    fail(f'unsupported archive member type: {name!r}')
            archive.extractall(extraction_root)
        bundle = extraction_root / args.root_name
        if not (bundle / 'bundle.json').is_file():
            fail('extracted bundle manifest is missing')
        subprocess.run(
            [sys.executable, str(repo / 'tools/faisal-build/verify_release_candidate_bundle.py'), '--repo', str(repo), '--bundle', str(bundle)],
            check=True,
        )
    print('FAISAL_RELEASE_CANDIDATE_ARCHIVE_OK checks=6')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_RELEASE_CANDIDATE_ARCHIVE_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
