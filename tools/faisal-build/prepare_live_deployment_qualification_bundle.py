#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,shutil,tarfile,time
from pathlib import Path
def sha(p):
 d=hashlib.sha256();
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): d.update(b)
 return d.hexdigest()
def cp(s,r,n):
 if not Path(s).is_file(): raise SystemExit('missing input '+str(s))
 d=r/n; d.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(s,d); return {'path':n,'sha256':sha(s),'bytes':Path(s).stat().st_size}
def main():
 p=argparse.ArgumentParser(); p.add_argument('--source-dir',type=Path,required=True); p.add_argument('--source-revision',required=True); p.add_argument('--deployment-evidence',type=Path,required=True); p.add_argument('--output-dir',type=Path,required=True); a=p.parse_args(); src=a.source_dir.resolve(); out=a.output_dir.resolve(); pid='faisal-live-deployment-'+a.source_revision[:12]; r=out/pid
 if r.exists(): shutil.rmtree(r)
 r.mkdir(parents=True); files={'baseline_deployment_evidence':cp(a.deployment_evidence,r,'baseline/m172-deployment-evidence.json')}
 for s,n in [('tools/faisal-build/verify_deployment_governance.py','controls/verify_deployment_governance.py'),('tools/faisal-build/verify_live_deployment_qualification.py','controls/verify_live_deployment_qualification.py'),('tools/faisal-build/run_production_release_gate.sh','controls/run_production_release_gate.sh'),('FAISAL-DEPLOYMENT-GOVERNANCE.md','scope/FAISAL-DEPLOYMENT-GOVERNANCE.md'),('FAISAL-PROGRAM-STATE.json','project/FAISAL-PROGRAM-STATE.json')]: files[n]=cp(src/s,r,n)
 m={'schema':'org.faisal.live-deployment-qualification-package.v1','package_id':pid,'generated_epoch':int(time.time()),'source_revision':a.source_revision,'status':'external_live_execution_required','files':files,'contract':{'minimum_nodes':3,'independent_hosts':True,'real_orchestrator':True,'migration_fence':True,'live_canary':True,'live_rollback':True,'persistent_recovery':True,'irreversible_action_compensation':True,'software_qemu_fixture_not_production':True}}
 mp=r/'qualification-package.json'; mp.write_text(json.dumps(m,indent=2,sort_keys=True)+'\n'); t={'schema':'org.faisal.live-deployment-qualification.v1','status':'template_pending_external_execution','source_revision':a.source_revision,'qualification_package':{'package_id':pid,'manifest_sha256':sha(mp)},'model_output_is_authority':False,'topology':{'independent_hosts':False,'node_count':0,'orchestrator_identity':None,'nodes':[]},'migration':{'executed_live':False,'from_revision':None,'to_revision':None,'state_compatible':False,'handoff_receipt':None},'fencing':{'before_generation':0,'after_generation':0,'stale_worker_denied':False},'canary':{'live':False,'health_receipt':False,'promotion_receipt':False,'failure_rollback_tested':False},'rollback':{'live':False,'target_revision':None,'target_digest':None,'recovery_verified':False,'idempotent':False},'irreversible_actions':{'actions_exercised':False,'compensation_plan_reviewed':False,'compensation_receipt':False,'idempotency_tested':False,'residual_risk_disposition':None},'markers':[],'limitations':['template only; real multi-host migration, rollback, restart, and irreversible-action compensation execution required']}
 (r/'live-deployment-qualification-template.json').write_text(json.dumps(t,indent=2,sort_keys=True)+'\n'); (r/'README.md').write_text(f'# FAISAL Live Deployment Qualification\n\nPackage `{pid}` binds to `{a.source_revision}`. M172 is software/QEMU baseline only. This package contains no credentials and cannot claim live qualification.\n'); (r/'SHA256SUMS').write_text('\n'.join(f'{sha(x)}  {x.relative_to(r)}' for x in sorted(x for x in r.rglob('*') if x.is_file()))+'\n'); arc=out/f'{pid}.tar.gz';
 with tarfile.open(arc,'w:gz') as z:z.add(r,arcname=r.name)
 shutil.copy2(mp,out/'qualification-package.json'); print(f'FAISAL_LIVE_DEPLOYMENT_PACKAGE_READY package={pid} manifest={out}/qualification-package.json archive={arc}'); print('manifest_sha256='+sha(out/'qualification-package.json')+' archive_sha256='+sha(arc))
if __name__=='__main__': main()
