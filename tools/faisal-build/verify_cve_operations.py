#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
SCHEMA='org.faisal.cve-operations.v1'
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
def verify(report,key,expected,now,max_age):
 rp=Path(report)
 if rp.suffix!='.json' or not rp.is_file() or not Path(str(rp)+'.sig').is_file() or not Path(key).is_file(): fail('CVE operations evidence, detached signature, and public key are required')
 r=subprocess.run(['openssl','dgst','-sha256','-verify',str(key),'-signature',str(rp)+'.sig',str(rp)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if r.returncode: fail('CVE operations evidence signature mismatch')
 d=load(rp)
 if d.get('schema')!=SCHEMA or d.get('status')!='operator_owned_cve_workflow_qualified': fail('CVE operations schema/status is not qualified')
 if d.get('source_revision')!=expected: fail('CVE operations source revision mismatch')
 if not isinstance(d.get('reviewed_epoch'),int) or d['reviewed_epoch']>now or now-d['reviewed_epoch']>max_age: fail('CVE operations evidence stale or timestamp invalid')
 if d.get('model_output_is_authority') is not False: fail('model output cannot authorize CVE operations')
 owner=d.get('operator_owner',{})
 required=('workflow_id','team','account_id','contact','escalation_contact','key_fingerprint','ack_receipt')
 if owner.get('live') is not True or owner.get('operator_confirmed') is not True or any(not isinstance(owner.get(k),str) or not owner[k] for k in required): fail('live operator-owned advisory workflow identity is incomplete')
 if any(token in owner.get('account_id','').lower() for token in ('sandbox','simulation','fixture','model')): fail('simulation identity cannot qualify live CVE ownership')
 sync=d.get('upstream_sync',{})
 if sync.get('live') is not True or not sync.get('job_id') or not sync.get('completed_epoch') or sync.get('completed_epoch')>now or sync.get('source_count',0)<3 or sync.get('all_sources_current') is not True or sync.get('auth_receipt') is None: fail('live upstream/CISA/NVD synchronization evidence is incomplete')
 sources=sync.get('sources',[])
 if len(sources)<3 or any(not isinstance(s,dict) or not s.get('id') or not s.get('url','').startswith('https://') or not isinstance(s.get('snapshot_sha256'),str) or len(s['snapshot_sha256'])!=64 or not s.get('retrieved_epoch') for s in sources): fail('authoritative synchronization snapshots are incomplete')
 life=d.get('lifecycle',{})
 for k in ('intake_receipt','triage_receipt','remediation_receipt','disclosure_receipt','post_release_review_receipt'):
  if not life.get(k): fail('CVE lifecycle receipt missing: '+k)
 if life.get('sla_policy_version') is None or life.get('overdue_open_advisories')!=0 or life.get('unresolved_blocking_advisories')!=0 or life.get('operator_escalation_tested') is not True: fail('CVE lifecycle SLA/backlog controls are incomplete')
 ledger=d.get('ledger',{})
 if not isinstance(ledger.get('path'),str) or not isinstance(ledger.get('sha256'),str) or len(ledger['sha256'])!=64 or ledger.get('validator_status')!='pass' or ledger.get('operator_signature_verified') is not True: fail('signed advisory ledger binding is incomplete')
 feedback=d.get('external_security_feedback',{})
 if feedback.get('live') is not True or not feedback.get('reviewer_identity') or not feedback.get('feedback_receipt') or not feedback.get('report_sha256') or len(feedback['report_sha256'])!=64 or feedback.get('candidate_source_revision')!=expected or feedback.get('remediation_retest_status')!='pass' or feedback.get('unresolved_critical_high')!=0 or feedback.get('feedback_integrated') is not True: fail('external security-review feedback loop is incomplete')
 disclosure=d.get('disclosure',{})
 if disclosure.get('policy_version') is None or disclosure.get('coordinated_process_tested') is not True or disclosure.get('embargo_and_publication_tested') is not True or disclosure.get('cna_status') not in {'assigned','not_applicable_with_rationale'}: fail('disclosure/CNA operational evidence is incomplete')
 if d.get('limitations') not in ([],None): fail('qualified CVE operations evidence cannot retain pending/simulation limitations')
 if d.get('production_status')!='operator_owned_workflow_only_other_release_gates_pending': fail('CVE production boundary missing or overstated')
 return d
def main():
 report=Path(os.environ.get('FAISAL_CVE_OPERATIONS_EVIDENCE','')); key=Path(os.environ.get('FAISAL_CVE_OPERATIONS_PUBLIC_KEY',os.environ.get('FAISAL_PUBLIC_KEY',''))); out=Path(os.environ.get('FAISAL_CVE_OPERATIONS_VERIFY_REPORT',str(report)+'.verification.tsv'))
 try:
  d=verify(report,key,os.environ.get('FAISAL_EXPECTED_SOURCE_REV',''),int(time.time()),int(os.environ.get('FAISAL_CVE_OPERATIONS_MAX_AGE_SECONDS',2592000))); out.parent.mkdir(parents=True,exist_ok=True); out.write_text('check\tstatus\tdetail\ncve_operations\tpass\t'+d['operator_owner']['workflow_id']+'\n'); print('FAISAL_CVE_OPERATIONS_OK'); return 0
 except Exception as e:
  out.parent.mkdir(parents=True,exist_ok=True); out.write_text('check\tstatus\tdetail\ncve_operations\tblocked\t'+str(e)+'\n'); print('FAISAL_CVE_OPERATIONS_BLOCKED reason='+str(e),file=sys.stderr); return 1
if __name__=='__main__': raise SystemExit(main())
