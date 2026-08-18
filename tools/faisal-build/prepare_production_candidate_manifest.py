#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            digest.update(chunk)
    return digest.hexdigest()

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--lts-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    build = args.lts_build.resolve()
    head = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    lts = '105f2b85e4c26305a79f5e584df6ebb705858d33'
    evidence = []
    names = [
        'm167-lts-6.18.44-forward-port-validation.json',
        'm169-cve-response-validation.json',
        'm170-physical-accelerator-qualification-validation.json',
        'm171-full-tls-replication-qualification-validation.json',
        'm172-deployment-governance-validation.json',
        'm173-external-security-review-validation.json',
        'm174-independent-builder-handoff-validation.json',
        'm175-physical-accelerator-handoff-validation.json',
        'm176-external-security-review-readiness-validation.json',
        'm177-signing-authority-operational-proof-validation.json',
        'm178-external-replication-qualification-readiness-validation.json',
        'm179-live-deployment-qualification-readiness-validation.json',
        'm180-lts-soak-requalification-validation.json',
        'm181-cve-operations-readiness-validation.json',
    ]
    for name in names:
        path = repo / 'tools/faisal-build/evidence' / name
        if path.is_file():
            evidence.append({'path': str(path.relative_to(repo)), 'sha256': sha(path)})
    manifest = {
        'schema': 'org.faisal.production-candidate.v1',
        'project': 'FAISAL',
        'candidate_id': 'faisal-lts-6.18.44-' + head[:12],
        'generated_epoch': int(time.time()),
        'status': 'bounded_candidate_not_production_approved',
        'repository_head': head,
        'lts_source_revision': lts,
        'artifact': {
            'bzImage_path': str(build / 'arch/x86/boot/bzImage'),
            'bzImage_sha256': sha(build / 'arch/x86/boot/bzImage'),
            'config_path': str(build / '.config'),
            'config_sha256': sha(build / '.config'),
            'required_config': {'CONFIG_CFS_BANDWIDTH': 'y'},
        },
        'evidence_index': evidence,
        'qualification_scope': {
            'linux_lts_build': True,
            'software_regressions': True,
            'qemu_regressions': True,
            'representative_tcg_soak': True,
            'physical_hardware': False,
            'independent_builder': False,
            'operator_signing_ceremony': False,
            'external_security_review': False,
            'external_multihost_replication': False,
            'live_multihost_deployment': False,
            'live_cve_operations': False,
        },
        'release_blockers': [
            'independent_external_builder_or_attested_farm',
            'operator_signing_ceremony_trusted_distribution_rotation_revocation',
            'physical_gpu_npu_vram_iommu_dma_vendor_driver',
            'independent_external_security_review_signed_disposition',
            'production_pki_external_multihost_replication_live_kms_attestation',
            'live_multihost_migration_rollback_irreversible_action_compensation',
            'operator_owned_cve_workflow_upstream_sync_external_feedback',
        ],
        'approval': {
            'status': 'blocked',
            'operator_approved': False,
            'authority': 'none',
            'model_output_is_authority': False,
            'signature_required': True,
            'signature_present': False,
        },
        'claims_not_made': [
            'production approval',
            'physical hardware qualification',
            'independent builder qualification',
            'live external security review',
            'live production PKI/KMS/TPM qualification',
            'zero-CVE or vulnerability-free status',
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print('FAISAL_PRODUCTION_CANDIDATE_MANIFEST_READY', args.output)

if __name__ == '__main__':
    main()
