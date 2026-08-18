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
 s=Path(s)
 if not s.is_file(): raise SystemExit('missing input '+str(s))
 d=r/n; d.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(s,d); return {'path':n,'sha256':sha(s),'bytes':s.stat().st_size}
def main():
 p=argparse.ArgumentParser(); p.add_argument('--source-dir',type=Path,required=True); p.add_argument('--source-revision',required=True); p.add_argument('--baseline-evidence',type=Path,required=True); p.add_argument('--output-dir',type=Path,required=True); a=p.parse_args(); src=a.source_dir.resolve(); out=a.output_dir.resolve(); pid='faisal-cve-operations-'+a.source_revision[:12]; r=out/pid
 if r.exists(): shutil.rmtree(r)
 r.mkdir(parents=True); files={'baseline_m169_evidence':cp(a.baseline_evidence,r,'baseline/m169-cve-response-validation.json')}
 for s,n in [('tools/faisal-build/verify_advisory_ledger.py','controls/verify_advisory_ledger.py'),('tools/faisal-build/verify_cve_operations.py','controls/verify_cve_operations.py'),('tools/faisal-build/run_production_release_gate.sh','controls/run_production_release_gate.sh'),('FAISAL-CVE-RESPONSE.md','scope/FAISAL-CVE-RESPONSE.md'),('tools/faisal-build/evidence/cve-operations-research-2026-08-18.md','scope/cve-operations-research.md'),('FAISAL-PROGRAM-STATE.json','project/FAISAL-PROGRAM-STATE.json')]: files[n]=cp(src/s,r,n)
 m={'schema':'org.faisal.cve-operations-package.v1','package_id':pid,'generated_epoch':int(time.time()),'source_revision':a.source_revision,'status':'live_operator_execution_required','files':files,'contract':{'operator_owned_workflow':True,'upstream_linux_cisa_nvd_sync':True,'lifecycle_sla_receipts':True,'ledger_signature_binding':True,'external_security_feedback':True,'cna_disclosure_handling':True,'simulation_is_not_production':True}}
 mp=r/'qualification-package.json'; mp.write_text(json.dumps(m,indent=2,sort_keys=True)+'\n'); t={'schema':'org.faisal.cve-operations.v1','status':'template_pending_live_operator_execution','source_revision':a.source_revision,'model_output_is_authority':False,'operator_owner':{'live':False,'operator_confirmed':False,'account_id':'sandbox-fixture'},'upstream_sync':{'live':False,'source_count':0,'all_sources_current':False},'lifecycle':{'overdue_open_advisories':None,'unresolved_blocking_advisories':None},'ledger':{'validator_status':'pending','operator_signature_verified':False},'external_security_feedback':{'live':False,'remediation_retest_status':'pending','feedback_integrated':False},'limitations':['template only; real operator ownership, upstream synchronization, lifecycle receipts, and external feedback are required']}
 (r/'cve-operations-template.json').write_text(json.dumps(t,indent=2,sort_keys=True)+'\n'); (r/'README.md').write_text(f'# FAISAL CVE Operations Handoff\n\nPackage `{pid}` binds to `{a.source_revision}`. M169 is a bounded schema baseline. This package contains no production credentials and cannot claim live ownership or synchronization.\n'); (r/'SHA256SUMS').write_text('\n'.join(f'{sha(x)}  {x.relative_to(r)}' for x in sorted(x for x in r.rglob('*') if x.is_file()))+'\n'); arc=out/f'{pid}.tar.gz';
 with tarfile.open(arc,'w:gz') as z:z.add(r,arcname=r.name)
 shutil.copy2(mp,out/'qualification-package.json'); print(f'FAISAL_CVE_OPERATIONS_PACKAGE_READY package={pid} manifest={out}/qualification-package.json archive={arc}'); print('manifest_sha256='+sha(out/'qualification-package.json')+' archive_sha256='+sha(arc))
if __name__=='__main__': main()
