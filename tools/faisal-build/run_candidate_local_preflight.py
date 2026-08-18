#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--provenance', type=Path, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--state', type=Path, required=True)
    args = p.parse_args()
    repo = args.repo.resolve()
    tools = repo / 'tools/faisal-build'
    checks = [
        ('candidate_manifest', ['python3', str(tools / 'verify_production_candidate_manifest.py')], {'FAISAL_PRODUCTION_CANDIDATE_MANIFEST': str(args.candidate.resolve())}, 'FAISAL_PRODUCTION_CANDIDATE_MANIFEST_OK'),
        ('provenance', ['python3', str(tools / 'verify_candidate_provenance.py'), '--repo', str(repo), '--build-manifest', str(args.provenance.resolve().parent / 'FAISAL-build-manifest.json'), '--sbom', str(args.provenance.resolve().parent / 'FAISAL-SBOM.spdx')], {}, 'FAISAL_CANDIDATE_PROVENANCE_OK'),
        ('provenance_alignment', ['python3', str(tools / 'verify_candidate_provenance_alignment.py'), '--repo', str(repo), '--candidate', str(args.candidate.resolve()), '--provenance', str(args.provenance.resolve())], {}, 'FAISAL_CANDIDATE_PROVENANCE_ALIGNMENT_OK'),
        ('consistency', ['python3', str(tools / 'audit_production_candidate_consistency.py'), '--repo', str(repo), '--manifest', str(args.candidate.resolve()), '--state', str(args.state.resolve())], {}, 'FAISAL_EVIDENCE_CONSISTENCY_AUDIT_OK'),
        ('freshness', ['python3', str(tools / 'audit_candidate_evidence_freshness.py'), '--repo', str(repo), '--candidate', str(args.candidate.resolve()), '--provenance', str(args.provenance.resolve()), '--evidence', str(args.evidence.resolve()), '--state', str(args.state.resolve())], {}, 'FAISAL_CANDIDATE_EVIDENCE_FRESHNESS_OK'),
    ]
    for name, command, extra_env, marker in checks:
        env = os.environ.copy()
        env.update(extra_env)
        result = subprocess.run(command, cwd=repo, env=env, text=True, capture_output=True)
        output = (result.stdout + result.stderr).strip()
        if result.returncode != 0 or marker not in output:
            print(f'FAISAL_LOCAL_PREFLIGHT_BLOCKED check={name}', file=sys.stderr)
            if output:
                print(output, file=sys.stderr)
            raise SystemExit(1)
        print(output)
    print(f'FAISAL_LOCAL_PREFLIGHT_OK checks={len(checks)}')


if __name__ == '__main__':
    main()
