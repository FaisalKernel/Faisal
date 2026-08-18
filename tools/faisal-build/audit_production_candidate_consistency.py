#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REQUIRED_BLOCKERS = {
    'independent_external_builder_or_attested_farm',
    'operator_signing_ceremony_trusted_distribution_rotation_revocation',
    'physical_gpu_npu_vram_iommu_dma_vendor_driver',
    'independent_external_security_review_signed_disposition',
    'production_pki_external_multihost_replication_live_kms_attestation',
    'live_multihost_migration_rollback_irreversible_action_compensation',
    'operator_owned_cve_workflow_upstream_sync_external_feedback',
}
PROTECTED = {
    'M63-COMPUTE-CONTEXT-DESIGN.md',
    'M63-SECURITY-REVIEW.md',
    'tools/faisal-build/evidence/upstream-kernel-release-research-2026-08-17.txt',
}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    manifest = json.loads(args.manifest.resolve().read_text())
    state = json.loads(args.state.resolve().read_text())
    checks = 0

    head = git(repo, 'rev-parse', 'HEAD')
    checks += 1
    if manifest.get('repository_head') != head:
        fail('manifest repository_head does not match git HEAD')
    checks += 1
    if state.get('current_head') != head:
        fail('program state current_head does not match git HEAD')
    tag = state.get('current_tag')
    checks += 1
    if not tag or git(repo, 'rev-parse', f'{tag}^{{commit}}') != head:
        fail('program state current_tag does not resolve to git HEAD')
    checks += 1
    if manifest.get('candidate_id') != 'faisal-lts-6.18.44-' + head[:12]:
        fail('candidate_id is not bound to current HEAD')

    checks += 1
    if manifest.get('status') != 'bounded_candidate_not_production_approved':
        fail('manifest status is not bounded and blocked')
    approval = manifest.get('approval', {})
    checks += 1
    if approval.get('status') != 'blocked' or approval.get('operator_approved') is not False:
        fail('manifest approval boundary is not blocked')
    checks += 1
    if approval.get('model_output_is_authority') is not False:
        fail('model output authority boundary is missing')
    scope = manifest.get('qualification_scope', {})
    checks += 1
    if scope.get('qemu_blocked_profiles') and scope.get('qemu_regressions') is True:
        fail('manifest contradicts its blocked QEMU profile')
    checks += 1
    if not REQUIRED_BLOCKERS.issubset(set(manifest.get('release_blockers', []))):
        fail('mandatory external release blockers are missing')

    for item in manifest.get('evidence_index', []):
        checks += 1
        path = repo / item['path']
        if not path.is_file() or digest(path) != item.get('sha256'):
            fail('evidence hash mismatch: ' + item.get('path', ''))

    staged = set(git(repo, 'diff', '--cached', '--name-only').splitlines())
    checks += 1
    if staged & PROTECTED:
        fail('protected file is staged: ' + sorted(staged & PROTECTED)[0])
    checks += 1
    tracked = set(git(repo, 'ls-files').splitlines())
    if tracked & PROTECTED:
        fail('protected file is tracked: ' + sorted(tracked & PROTECTED)[0])

    print(f'FAISAL_EVIDENCE_CONSISTENCY_AUDIT_OK checks={checks} head={head}')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_EVIDENCE_CONSISTENCY_AUDIT_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
