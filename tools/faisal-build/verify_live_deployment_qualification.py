#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
SCHEMA='org.faisal.live-deployment-qualification.v1'
MARKERS={'LIVE_EXTERNAL_ORCHESTRATOR_IDENTITY_OK','MULTIHOST_MIGRATION_EXECUTED_OK','WORKER_FENCE_ADVANCED_AND_STALE_DENIED_OK','CANARY_PROMOTION_AND_HEALTH_RECEIPT_OK','LIVE_ROLLBACK_TO_PREVIOUS_ACTIVE_OK','PERSISTENT_STATE_RECOVERY_AFTER_RESTART_OK','IRREVERSIBLE_ACTION_COMPENSATION_RECEIPT_OK','COMPENSATION_IDEMPOTENCY_AND_RESIDUAL_RISK_OK'}
def fail(m): raise ValueError(m)
def sha(p):
 d=hashlib.sha256();
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): d.update(b)
 return d.hexdigest()
def load(p):
 try: v=json.loads(Path(p).read_text())
 except Exception as e: fail(f'invalid JSON: {e}')
 if not isinstance(v,dict): fail('JSON object required')
 return v
def verify(report,key,expected,package,now,max_age):
 if Path(report).suffix!='.json' or not Path(report).is_file() or not Path(str(report)+'.sig').is_file() or not Path(key).is_file(): fail('live deployment report, detached signature, and public key are required')
 r=subprocess.run(['openssl','dgst','-sha256','-verify',str(key),'-signature',str(report)+'.sig',str(report)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if r.returncode: fail('live deployment evidence signature mismatch')
 d=load(report)
 if d.get('schema')!=SCHEMA or d.get('status')!='live_multihost_deployment_qualified': fail('live deployment status/schema is not qualified')
 if d.get('source_revision')!=expected: fail('deployment source revision mismatch')
 if not isinstance(d.get('reviewed_epoch'),int) or d['reviewed_epoch']>now or now-d['reviewed_epoch']>max_age: fail('deployment evidence stale or timestamp invalid')
 if d.get('model_output_is_authority') is not False: fail('model output cannot authorize deployment')
 if package:
  p=load(package); q=d.get('qualification_package',{})
  if q.get('package_id')!=p.get('package_id') or q.get('manifest_sha256')!=sha(package) or p.get('source_revision')!=expected: fail('deployment evidence package binding mismatch')
 topo=d.get('topology',{})
 if topo.get('independent_hosts') is not True or topo.get('node_count',0)<3 or not topo.get('orchestrator_identity'): fail('live multi-host orchestrator topology required')
 nodes=topo.get('nodes',[]); ids=set(); hosts=set()
 for n in nodes:
  if not isinstance(n,dict) or not n.get('node_id') or not n.get('host_id') or n['node_id'] in ids or n['host_id'] in hosts or any(x in str(n.get('endpoint','')).lower() for x in ('localhost','127.0.0.1','::1')): fail('distinct non-loopback deployment nodes required')
  ids.add(n['node_id']); hosts.add(n['host_id'])
 mig=d.get('migration',{})
 if not mig.get('executed_live') or not mig.get('from_revision') or not mig.get('to_revision') or mig.get('from_revision')==mig.get('to_revision') or mig.get('state_compatible') is not True or not mig.get('handoff_receipt'): fail('live migration and handoff receipt incomplete')
 fence=d.get('fencing',{})
 if not isinstance(fence.get('before_generation'),int) or not isinstance(fence.get('after_generation'),int) or fence['after_generation']<=fence['before_generation'] or fence.get('stale_worker_denied') is not True: fail('migration fencing evidence incomplete')
 can=d.get('canary',{})
 if can.get('live') is not True or can.get('health_receipt') is not True or can.get('promotion_receipt') is not True or can.get('failure_rollback_tested') is not True: fail('live canary evidence incomplete')
 rb=d.get('rollback',{})
 if rb.get('live') is not True or rb.get('target_revision')!=mig.get('from_revision') or rb.get('target_digest')!=d.get('previous_active_digest') or rb.get('recovery_verified') is not True or rb.get('idempotent') is not True: fail('live rollback/recovery evidence incomplete')
 ext=d.get('irreversible_actions',{})
 if ext.get('actions_exercised') is not True or ext.get('compensation_plan_reviewed') is not True or ext.get('compensation_receipt') is not True or ext.get('idempotency_tested') is not True or not isinstance(ext.get('residual_risk_disposition'), str) or not ext.get('residual_risk_disposition'): fail('irreversible-action compensation evidence incomplete')
 if set(d.get('markers',[]))<MARKERS: fail('live deployment markers missing: '+','.join(sorted(MARKERS-set(d.get('markers',[])))))
 if d.get('limitations'): fail('qualified live deployment report cannot retain limitations')
 return d
def main():
 report=Path(os.environ.get('FAISAL_LIVE_DEPLOYMENT_EVIDENCE','')); key=Path(os.environ.get('FAISAL_LIVE_DEPLOYMENT_PUBLIC_KEY',os.environ.get('FAISAL_PUBLIC_KEY',''))); package=Path(os.environ['FAISAL_LIVE_DEPLOYMENT_PACKAGE']) if os.environ.get('FAISAL_LIVE_DEPLOYMENT_PACKAGE') else None; out=Path(os.environ.get('FAISAL_LIVE_DEPLOYMENT_VERIFY_REPORT',str(report)+'.verification.tsv'))
 try:
  d=verify(report,key,os.environ.get('FAISAL_EXPECTED_SOURCE_REV',''),package,int(time.time()),int(os.environ.get('FAISAL_LIVE_DEPLOYMENT_MAX_AGE_SECONDS',2592000))); out.parent.mkdir(parents=True,exist_ok=True); out.write_text('check\tstatus\tdetail\nlive_deployment\tpass\t'+d['migration']['to_revision']+'\n'); print('FAISAL_LIVE_DEPLOYMENT_QUALIFICATION_OK'); return 0
 except Exception as e:
  out.parent.mkdir(parents=True,exist_ok=True); out.write_text('check\tstatus\tdetail\nlive_deployment\tblocked\t'+str(e)+'\n'); print('FAISAL_LIVE_DEPLOYMENT_QUALIFICATION_BLOCKED reason='+str(e),file=sys.stderr); return 1
if __name__=='__main__': raise SystemExit(main())
