#!/usr/bin/env python3
"""Prepare public handoff material for external replication qualification."""
from __future__ import annotations
import argparse, hashlib, json, shutil, tarfile, time
from pathlib import Path
SCHEMA="org.faisal.external-replication-qualification-package.v1"
def sha256(p:Path)->str:
 d=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): d.update(b)
 return d.hexdigest()
def cp(src:Path,root:Path,name:str)->dict:
 if not src.is_file(): raise SystemExit(f'missing input: {src}')
 dst=root/name; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,dst)
 return {'path':name,'sha256':sha256(src),'bytes':src.stat().st_size}
def main()->int:
 p=argparse.ArgumentParser(); p.add_argument('--source-dir',type=Path,required=True); p.add_argument('--source-revision',required=True); p.add_argument('--software-evidence',type=Path,required=True); p.add_argument('--output-dir',type=Path,required=True); a=p.parse_args()
 src=a.source_dir.resolve(); out=a.output_dir.resolve(); package_id=f'faisal-external-replication-{a.source_revision[:12]}'
 root=out/package_id
 if root.exists(): shutil.rmtree(root)
 root.mkdir(parents=True)
 rel=[('tools/faisal-replication/faisal_replication.proto','source/faisal_replication.proto'),('tools/faisal-replication/faisal_replication_daemon.py','source/faisal_replication_daemon.py'),('tools/faisal-replication/faisal_replication_providers.py','source/faisal_replication_providers.py'),('tools/faisal-replication/full_tls_replication_fixture.py','source/full_tls_replication_fixture.py'),('tools/faisal-replication/live_partition_fault_test.py','source/live_partition_fault_test.py'),('tools/faisal-replication/run_full_tls_replication_fixture.sh','source/run_full_tls_replication_fixture.sh'),('tools/faisal-replication/run_live_partition_fault_test.sh','source/run_live_partition_fault_test.sh'),('tools/faisal-replication/run_vault_dev_integration.sh','source/run_vault_dev_integration.sh'),('tools/faisal-replication/FAISAL-REPLICATION-PROTOCOL.md','scope/FAISAL-REPLICATION-PROTOCOL.md'),('FAISAL-REPLICATION-QUALIFICATION.md','scope/FAISAL-REPLICATION-QUALIFICATION.md'),('tools/faisal-build/verify_replication_qualification.py','controls/verify_replication_qualification.py'),('tools/faisal-build/verify_external_replication_qualification.py','controls/verify_external_replication_qualification.py'),('tools/faisal-build/run_production_release_gate.sh','controls/run_production_release_gate.sh'),('FAISAL-PROGRAM-STATE.json','project/FAISAL-PROGRAM-STATE.json')]
 files={'software_fixture_evidence':cp(a.software_evidence,root,'baseline/m171-replication-evidence.json')}
 for s,n in rel: files[n]=cp(src/s,root,n)
 manifest={'schema':SCHEMA,'package_id':package_id,'generated_epoch':int(time.time()),'status':'external_execution_required','source_revision':a.source_revision,'files':files,'qualification_contract':{'minimum_nodes':3,'independent_hosts':True,'non_loopback_endpoints':True,'production_pki':True,'live_kms_or_vault':True,'hardware_attestation':True,'live_partition_and_recovery':True,'deployment_restart_rollback':True,'software_fixture_is_not_production':True}}
 mp=root/'qualification-package.json'; mp.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
 template={'schema':'org.faisal.external-replication-qualification.v1','status':'template_pending_external_execution','source_revision':a.source_revision,'qualification_package':{'package_id':package_id,'manifest_sha256':sha256(mp)},'model_output_is_authority':False,'candidate':{'protocol_sha256':files['source/faisal_replication.proto']['sha256'],'artifact_manifest_sha256':'TO_BE_FILLED','build_id':'TO_BE_FILLED'},'topology':{'node_count':0,'independent_hosts':False,'external_network':False,'nodes':[]},'production_pki':{'live':False,'ca_issuer':'TO_BE_FILLED','trust_bundle_sha256':'TO_BE_FILLED','revocation_check':False,'rotation_tested':False},'kms_or_vault':{'live':False,'provider':'TO_BE_FILLED','key_id':'TO_BE_FILLED','sign_verify_receipt':None,'rotation_tested':False,'failure_denial_tested':False},'hardware_attestation':{'live':False,'provider':'TO_BE_FILLED','quote_verified':False,'key_non_exportability_verified':False},'deployment':{'orchestrator':'TO_BE_FILLED','restart_tested':False,'rollback_tested':False,'persistent_state_verified':False},'markers':[],'quorum':{'majority_commit_verified':False,'minority_commit_denied':False},'limitations':['template only; external multi-host, production PKI, live KMS/Vault, hardware attestation, and real deployment execution are required']}
 (root/'external-qualification-template.json').write_text(json.dumps(template,indent=2,sort_keys=True)+'\n')
 (root/'README.md').write_text(f'# FAISAL External Replication Qualification\n\nPackage `{package_id}` binds review to source `{a.source_revision}`. The M171 software fixture is baseline evidence only. This package contains no production credentials and cannot claim external qualification.\n')
 sums=[f'{sha256(x)}  {x.relative_to(root)}' for x in sorted(x for x in root.rglob('*') if x.is_file())]; (root/'SHA256SUMS').write_text('\n'.join(sums)+'\n')
 archive=out/f'{package_id}.tar.gz'; archive.parent.mkdir(parents=True,exist_ok=True)
 with tarfile.open(archive,'w:gz') as t:t.add(root,arcname=root.name)
 final=out/'qualification-package.json'; shutil.copy2(mp,final)
 print(f'FAISAL_EXTERNAL_REPLICATION_PACKAGE_READY package={package_id} manifest={final} archive={archive}'); print(f'manifest_sha256={sha256(final)} archive_sha256={sha256(archive)}'); return 0
if __name__=='__main__': raise SystemExit(main())
