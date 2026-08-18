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
        'm183-uapi-checkpatch-validation.json',
        'm184-driver-checkpatch-validation.json',
        'm185-qemu-regression-validation.json',
        'm186-driver-style-validation.json',
        'm187-world-queue-helper-validation.json',
        'm188-queue-overflow-validation.json',
        'm189-write-side-lifecycle-validation.json',
        'm190-write-side-state-validation.json',
        'm191-graph-telemetry-qemu-validation.json',
        'm192-world-state-hardened-qemu-validation.json',
        'm193-graph-fault-qemu-validation.json',
        'm194-durable-execution-recovery-validation.json',
        'm195-self-healing-hardened-qemu-validation.json',
        'm196-concurrent-ipc-hardened-qemu-validation.json',
        'm197-cross-subsystem-hardened-qemu-validation.json',
        'm198-world-sync-write-fault-hardened-qemu-validation.json',
        'm199-graph-world-multiop-hardened-qemu-validation.json',
        'm200-world-model-router-profile-classification-validation.json',
        'm201-legacy-qemu-wrapper-hardening-validation.json',
        'm202-end-to-end-hardened-qemu-validation.json',
        'm203-unqualified-legacy-qemu-fail-closed-validation.json',
        'm204-production-candidate-consistency-validation.json',
        'm205-current-lts-provenance-consistency-validation.json',
        'm206-candidate-provenance-alignment-validation.json',
        'm207-candidate-evidence-freshness-validation.json',
        'm208-unified-local-candidate-preflight-validation.json',
        'm209-production-gate-local-preflight-validation.json',
        'm210-release-gate-report-integrity-validation.json',
        'm211-local-gate-summary-validation.json',
        'm212-local-gate-summary-reproducibility-validation.json',
        'm213-release-candidate-bundle-validation.json',
        'm214-release-candidate-archive-validation.json',
        'm215-release-attestation-validation.json',
        'm216-release-gate-attestation-integration-validation.json',
        'm217-external-qualification-intake-validation.json',
        'm218-external-qualification-gate-validation.json',
        'm219-production-readiness-boundary-validation.json',
        'm220-release-gate-boundary-integration-validation.json',
        'm221-external-blocker-coverage-validation.json',
        'm222-aios-parity-urgency-scheduling-validation.json',
        'm223-inference-objective-contract-validation.json',
        'm224-preempt-rt-contract-validation.json',
        'm225-kubernetes-fleet-intent-validation.json',
        'm226-accelerator-fabric-validation.json',
        'm227-autonomous-model-action-validation.json',
        'm228-sandbox-execution-contract-validation.json',
        'm229-experience-evidence-contract-validation.json',
        'm230-adaptive-model-routing-validation.json',
        'm231-correlated-recovery-decision-validation.json',
        'm232-verified-research-consensus-validation.json',
        'm233-world-reconciliation-validation.json',
        'm234-trace-correlation-validation.json',
        'm235-browser-interaction-verification-validation.json',
        # M182 records the manifest digest; excluding it avoids a hash cycle.
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
            'qemu_regressions': False,
            'qemu_qualified_profiles': [
                'acpi_off_2vcpu_16384',
                'acpi_on_1vcpu_4096',
            ],
            'qemu_blocked_profiles': [
                'acpi_on_2vcpu_4096_rcu_preempt_stall',
            ],
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
