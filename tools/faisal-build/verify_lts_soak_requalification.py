#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
SCHEMA='org.faisal.lts-soak-requalification.v1'
DIAGNOSTICS=('rcu: .*stall','BUG:','Oops:','kernel panic','KASAN:','KCSAN:','WARNING:.*kernel','general protection fault','unable to handle kernel','kernel BUG')
def fail(m): raise ValueError(m)
def sha(p):
 d=hashlib.sha256();
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b): d.update(b)
 return d.hexdigest()
def load(p):
 try: v=json.loads(Path(p).read_text())
 except Exception as e: fail(f'invalid JSON: {e}')
 if not isinstance(v,dict): fail('JSON object required')
 return v
def verify(report,key,expected,now,max_age):
 if Path(report).suffix!='.json' or not Path(report).is_file() or not Path(str(report)+'.sig').is_file() or not Path(key).is_file(): fail('LTS soak evidence, detached signature, and public key are required')
 r=subprocess.run(['openssl','dgst','-sha256','-verify',str(key),'-signature',str(report)+'.sig',str(report)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if r.returncode: fail('LTS soak evidence signature mismatch')
 d=load(report)
 if d.get('schema')!=SCHEMA or d.get('status')!='representative_lts_soak_requalified': fail('LTS soak status/schema is not qualified')
 if d.get('source_revision')!=expected: fail('LTS soak source revision mismatch')
 if not isinstance(d.get('recorded_epoch'),int) or d['recorded_epoch']>now or now-d['recorded_epoch']>max_age: fail('LTS soak evidence stale or timestamp invalid')
 if d.get('model_output_is_authority') is not False: fail('model output cannot authorize LTS qualification')
 if d.get('lts_source_revision')!='105f2b85e4c26305a79f5e584df6ebb705858d33' or d.get('bzimage_sha256')!='8766f1019d80598c7982d91d89d7df27385a91ca7ea17d114d8869267204870b' or d.get('config_sha256')!='2c282274f1f716e2b1135b0a1fb819f99525dbe099ea0d31f1b3a2676f980e06': fail('LTS source/artifact/config binding mismatch')
 if d.get('config',{}).get('CONFIG_CFS_BANDWIDTH')!='y': fail('CONFIG_CFS_BANDWIDTH=y is required')
 profiles=d.get('profiles',{})
 bounded=profiles.get('bounded_one_vcpu'); rep=profiles.get('representative_two_vcpu')
 for name,p in (('bounded_one_vcpu',bounded),('representative_two_vcpu',rep)):
  if not isinstance(p,dict) or p.get('result')!='pass' or p.get('qemu_acceleration')!='tcg' or p.get('qemu_acpi')!='off' or p.get('marker_driven_exit') is not True or p.get('diagnostics') not in ([],None): fail(f'{name} profile incomplete or diagnostic-bearing')
  if not isinstance(p.get('rounds'),int) or p['rounds']<2 or not isinstance(p.get('iterations_per_round'),int) or p['iterations_per_round']<=0 or not p.get('summary_sha256'): fail(f'{name} measurements incomplete')
 if rep.get('qemu_smp')!=2 or rep.get('rounds')<3 or rep.get('iterations_per_round')<16384: fail('representative two-vCPU threshold not met')
 if bounded.get('qemu_smp')!=1 or bounded.get('rounds')<2 or bounded.get('iterations_per_round')<64: fail('bounded one-vCPU threshold not met')
 if d.get('rcu_stall_reproduction',{}).get('old_profile_rejected') is not True or d.get('rcu_stall_reproduction',{}).get('mitigation')!='qemu_pc_acpi_off_and_marker_driven_exit': fail('known RCU-stall reproduction and mitigation evidence missing')
 if d.get('kernel_diagnostics') not in ([],None): fail('kernel diagnostics remain in completed qualification')
 if d.get('production_status')!='representative_tcg_qualification_only': fail('LTS production boundary missing or overstated')
 return d
def main():
 report=Path(os.environ.get('FAISAL_LTS_SOAK_EVIDENCE','')); key=Path(os.environ.get('FAISAL_PUBLIC_KEY','')); out=Path(os.environ.get('FAISAL_LTS_SOAK_VERIFY_REPORT',str(report)+'.verification.tsv'))
 try:
  d=verify(report,key,os.environ.get('FAISAL_EXPECTED_SOURCE_REV',''),int(time.time()),int(os.environ.get('FAISAL_LTS_SOAK_MAX_AGE_SECONDS',2592000))); out.parent.mkdir(parents=True,exist_ok=True); out.write_text('check\tstatus\tdetail\nlts_soak\tpass\trepresentative_two_vcpu_tcg\n'); print('FAISAL_LTS_SOAK_REQUALIFICATION_OK'); return 0
 except Exception as e:
  out.parent.mkdir(parents=True,exist_ok=True); out.write_text('check\tstatus\tdetail\nlts_soak\tblocked\t'+str(e)+'\n'); print('FAISAL_LTS_SOAK_REQUALIFICATION_BLOCKED reason='+str(e),file=sys.stderr); return 1
if __name__=='__main__': raise SystemExit(main())
