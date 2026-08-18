#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,sys
from pathlib import Path
REQ=['independent_external_builder_or_attested_farm','operator_signing_ceremony_trusted_distribution_rotation_revocation','physical_gpu_npu_vram_iommu_dma_vendor_driver','independent_external_security_review_signed_disposition','production_pki_external_multihost_replication_live_kms_attestation','live_multihost_migration_rollback_irreversible_action_compensation','operator_owned_cve_workflow_upstream_sync_external_feedback']
def fail(m): raise ValueError(m)
def sha(p):
 d=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): d.update(b)
 return d.hexdigest()
def main():
 p=Path(os.environ.get('FAISAL_PRODUCTION_CANDIDATE_MANIFEST','')); d=json.loads(p.read_text())
 if d.get('schema')!='org.faisal.production-candidate.v1': fail('candidate schema mismatch')
 if d.get('status')!='bounded_candidate_not_production_approved': fail('candidate status overstates qualification')
 if d.get('approval',{}).get('operator_approved') is not False or d.get('approval',{}).get('status')!='blocked' or d.get('approval',{}).get('authority')!='none': fail('candidate approval boundary is not blocked')
 if d.get('approval',{}).get('model_output_is_authority') is not False: fail('model output cannot authorize candidate')
 scope=d.get('qualification_scope',{})
 if any(scope.get(k) is True for k in ('physical_hardware','independent_builder','operator_signing_ceremony','external_security_review','external_multihost_replication','live_multihost_deployment','live_cve_operations')): fail('candidate scope falsely claims external qualification')
 if scope.get('qemu_blocked_profiles') and scope.get('qemu_regressions') is True: fail('candidate claims full QEMU qualification while blocked profiles are recorded')
 if not all(x in d.get('release_blockers',[]) for x in REQ): fail('mandatory production blockers missing from manifest')
 art=d.get('artifact',{}); bp=Path(art.get('bzImage_path','')); cp=Path(art.get('config_path',''))
 if not bp.is_file() or sha(bp)!=art.get('bzImage_sha256'): fail('bzImage binding mismatch')
 if not cp.is_file() or sha(cp)!=art.get('config_sha256'): fail('config binding mismatch')
 if art.get('required_config',{}).get('CONFIG_CFS_BANDWIDTH')!='y' or 'CONFIG_CFS_BANDWIDTH=y' not in cp.read_text(): fail('required scheduler config missing')
 for e in d.get('evidence_index',[]):
  f=Path('/home/ubuntu/agi-kernel/linux')/e['path']
  if not f.is_file() or sha(f)!=e.get('sha256'): fail('evidence index mismatch: '+e.get('path',''))
 print('FAISAL_PRODUCTION_CANDIDATE_MANIFEST_OK')
if __name__=='__main__':
 try: main()
 except Exception as e: print('FAISAL_PRODUCTION_CANDIDATE_MANIFEST_BLOCKED reason='+str(e),file=sys.stderr); raise SystemExit(1)
