#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--provenance', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()

    repo = args.repo.resolve()
    summary_path = args.summary.resolve()
    summary = json.loads(summary_path.read_text())
    generated_at = summary.get('generated_at')
    if not isinstance(generated_at, str) or not generated_at.endswith('Z'):
        fail('summary generated_at is not a UTC Z timestamp')

    verifier = repo / 'tools/faisal-build/verify_local_gate_summary.py'
    generator = repo / 'tools/faisal-build/generate_local_gate_summary.py'
    subprocess.run(
        [sys.executable, str(verifier), '--repo', str(repo), '--summary', str(summary_path)],
        check=True,
    )

    with tempfile.TemporaryDirectory(prefix='faisal-m212-summary-') as temp:
        regenerated = Path(temp) / 'FAISAL-local-gate-summary.json'
        subprocess.run(
            [
                sys.executable,
                str(generator),
                '--repo', str(repo),
                '--candidate', str(args.candidate.resolve()),
                '--provenance', str(args.provenance.resolve()),
                '--evidence', str(args.evidence.resolve()),
                '--state', str(args.state.resolve()),
                '--report', str(args.report.resolve()),
                '--generated-at', generated_at,
                '--output', str(regenerated),
            ],
            check=True,
        )
        regenerated_summary = json.loads(regenerated.read_text())
        if regenerated_summary != summary:
            fail('summary regeneration differs from recorded summary')

    print('FAISAL_LOCAL_GATE_SUMMARY_REPRODUCIBLE_OK checks=2')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_LOCAL_GATE_SUMMARY_REPRODUCIBILITY_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
