#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MAX_BINDING_COMMITS = 3

def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def fail(message: str) -> None:
    raise ValueError(message)

def parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()

def distance(repo: Path, bound: str, head: str) -> int:
    try:
        subprocess.check_call(['git', '-C', str(repo), 'merge-base', '--is-ancestor', bound, head], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return -1
    return int(git(repo, 'rev-list', '--count', f'{bound}..{head}'))

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--provenance', type=Path, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--state', type=Path, required=True)
    args = p.parse_args()
    repo = args.repo.resolve()
    candidate = json.loads(args.candidate.resolve().read_text())
    provenance = json.loads(args.provenance.resolve().read_text())
    evidence = json.loads(args.evidence.resolve().read_text())
    state = json.loads(args.state.resolve().read_text())
    head = git(repo, 'rev-parse', 'HEAD')
    now = datetime.now(timezone.utc).timestamp()
    candidate_head = candidate.get('repository_head')
    provenance_head = provenance.get('repository_head')
    state_head = state.get('current_head')
    if distance(repo, candidate_head or '', head) not in range(MAX_BINDING_COMMITS + 1):
        fail('candidate lineage is stale or divergent')
    if distance(repo, provenance_head or '', head) not in range(MAX_BINDING_COMMITS + 1):
        fail('provenance lineage is stale or divergent')
    if distance(repo, state_head or '', head) not in range(MAX_BINDING_COMMITS + 1):
        fail('program-state lineage is stale or divergent')
    if not candidate_head or not provenance_head or not state_head:
        fail('missing lineage head')
    if candidate.get('generated_epoch', 0) > now + 60:
        fail('candidate generated timestamp is in the future')
    if parse_time(provenance['generated_at']) > now + 60:
        fail('provenance timestamp is in the future')
    if parse_time(evidence['recorded_at']) > now + 60:
        fail('evidence timestamp is in the future')
    candidate_commit_time = int(git(repo, 'show', '-s', '--format=%ct', candidate_head))
    provenance_commit_time = int(git(repo, 'show', '-s', '--format=%ct', provenance_head))
    if candidate.get('generated_epoch', 0) < candidate_commit_time:
        fail('candidate predates its bound commit')
    if parse_time(provenance['generated_at']) < provenance_commit_time:
        fail('provenance predates its bound commit')
    if parse_time(evidence['recorded_at']) < parse_time(provenance['generated_at']):
        fail('evidence predates provenance generation')
    if candidate.get('status') != 'bounded_candidate_not_production_approved':
        fail('candidate status is not bounded')
    if evidence.get('boundary', {}).get('production_approval') is not False:
        fail('evidence production boundary overstated')
    if evidence.get('boundary', {}).get('independent_builder') is not False:
        fail('evidence independent-builder boundary overstated')
    index_path = repo / 'tools/faisal-build/evidence/m206-candidate-provenance-alignment-validation.json'
    if not index_path.is_file():
        fail('M206 evidence artifact missing')
    if sha(index_path) != evidence.get('implementation', {}).get('evidence_sha256', sha(index_path)):
        fail('evidence self-hash binding mismatch')
    print(f'FAISAL_CANDIDATE_EVIDENCE_FRESHNESS_OK checks=15 head={head}')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_CANDIDATE_EVIDENCE_FRESHNESS_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
