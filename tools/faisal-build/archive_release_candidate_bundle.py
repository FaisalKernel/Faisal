#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import tarfile
from pathlib import Path


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--root-name', default='faisal-release-candidate')
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    output = args.output.resolve()
    if not (bundle / 'bundle.json').is_file():
        raise FileNotFoundError('bundle.json is missing')
    output.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(path for path in bundle.rglob('*') if path.is_file())
    with output.open('wb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for path in files:
                    relative = path.relative_to(bundle).as_posix()
                    arcname = f'{args.root_name}/{relative}'
                    data = path.read_bytes()
                    info = tarfile.TarInfo(arcname)
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ''
                    info.gname = ''
                    archive.addfile(info, __import__('io').BytesIO(data))
    print(f'FAISAL_RELEASE_CANDIDATE_ARCHIVE_READY path={output} sha256={sha(output)} files={len(files)}')


if __name__ == '__main__':
    main()
