#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def copy_file(source: Path, destination: Path, bundle_root: Path, role: str, records: list[dict]) -> None:
    source = source.resolve()
    if not source.is_file():
        raise FileNotFoundError(f'missing {role}: {source}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    records.append({
        'role': role,
        'path': destination.relative_to(bundle_root).as_posix(),
        'sha256': sha(destination),
        'size': destination.stat().st_size,
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--provenance', type=Path, required=True)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    repo = args.repo.resolve()
    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    candidate = json.loads(args.candidate.resolve().read_text())
    state = json.loads(args.state.resolve().read_text())
    provenance = json.loads(args.provenance.resolve().read_text())
    records: list[dict] = []

    copy_file(args.candidate, output / 'candidate/production-candidate.json', output, 'candidate_manifest', records)
    copy_file(args.provenance, output / 'provenance/FAISAL-build-manifest.json', output, 'build_manifest', records)
    sbom = args.provenance.parent / 'FAISAL-SBOM.spdx'
    copy_file(sbom, output / 'provenance/FAISAL-SBOM.spdx', output, 'sbom', records)
    copy_file(args.summary, output / 'summary/FAISAL-local-gate-summary.json', output, 'local_gate_summary', records)
    copy_file(args.state, output / 'state/FAISAL-PROGRAM-STATE.json', output, 'program_state', records)
    copy_file(args.report, output / 'report/FAISAL-production-release-gate.tsv', output, 'release_gate_report', records)

    seen_names: set[str] = set()
    for entry in candidate.get('evidence_index', []):
        source = repo / Path(entry.get('path', ''))
        name = source.name
        if not name or name in seen_names:
            raise ValueError(f'duplicate or invalid evidence basename: {name!r}')
        seen_names.add(name)
        copy_file(source, output / 'evidence' / name, output, f'evidence:{name}', records)

    artifact = candidate.get('artifact', {})
    copy_file(Path(artifact['bzImage_path']), output / 'artifacts/bzImage', output, 'kernel_image', records)
    copy_file(Path(artifact['config_path']), output / 'artifacts/.config', output, 'kernel_config', records)

    manifest = {
        'schema': 'org.faisal.release-candidate-bundle.v1',
        'project': 'FAISAL',
        'status': 'bounded_candidate_bundle_not_production_approved',
        'candidate_id': candidate.get('candidate_id'),
        'repository_head': candidate.get('repository_head'),
        'current_head': state.get('current_head'),
        'current_tag': state.get('current_tag'),
        'provenance_head': provenance.get('repository_head'),
        'files': sorted(records, key=lambda item: item['path']),
        'boundary': {
            'independent_builder': False,
            'operator_signature': False,
            'physical_hardware': False,
            'external_security_review': False,
            'production_approval': False,
            'model_output_is_authority': False,
        },
    }
    (output / 'bundle.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(output)


if __name__ == '__main__':
    main()
