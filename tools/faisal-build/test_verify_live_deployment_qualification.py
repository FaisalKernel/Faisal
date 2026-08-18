#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,subprocess,tempfile,time
from pathlib import Path
import verify_live_deployment_qualification as v
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 root=Path(tempfile.mkdtemp(prefix='faisal-live-deploy-test-')); key=root/'key.pem'; pub=root/'pub.pem'; subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(key)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); os.chmod(key,0o600); subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(pub)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 pkg=Path('/home/ubuntu/agi-kernel/build/m179-live-deployment/qualification-package.json'); p=json.loads(pkg.read_text()); pc=root/'qualification-package.json'; pc.write_bytes(pkg.read_bytes()); rev=p['source_revision']; now=int(time.time())
 d={'schema':v.SCHEMA,'status':'live_multihost_deployment_qualified','source_revision':rev,'reviewed_epoch':now,'model_output_is_authority':False,'qualification_package':{'package_id':p['package_id'],'manifest_sha256':sha(pc)},'topology':{'independent_hosts':True,'node_count':3,'orchestrator_identity':'prod-orchestrator-01','nodes':[{'node_id':'n1','host_id':'h1','endpoint':'10.0.0.11:1'},{'node_id':'n2','host_id':'h2','endpoint':'10.0.0.12:1'},{'node_id':'n3','host_id':'h3','endpoint':'10.0.0.13:1'}]},'migration':{'executed_live':True,'from_revision':'old','to_revision':'new','state_compatible':True,'handoff_receipt':'handoff-1'},'fencing':{'before_generation':10,'after_generation':11,'stale_worker_denied':True},'canary':{'live':True,'health_receipt':True,'promotion_receipt':True,'failure_rollback_tested':True},'previous_active_digest':'a'*64,'rollback':{'live':True,'target_revision':'old','target_digest':'a'*64,'recovery_verified':True,'idempotent':True},'irreversible_actions':{'actions_exercised':True,'compensation_plan_reviewed':True,'compensation_receipt':True,'idempotency_tested':True,'residual_risk_disposition':'none'},'markers':sorted(v.MARKERS),'limitations':[]}
 rp=root/'report.json'; rp.write_text(json.dumps(d,sort_keys=True,separators=(',',':'))+'\n'); subprocess.run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(rp)+'.sig',str(rp)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); v.verify(rp,pub,rev,pc,now,3600)
 for field in ('loopback','compensation','fence','pending'):
  b=json.loads(rp.read_text())
  if field=='loopback': b['topology']['nodes'][0]['endpoint']='127.0.0.1:1'
  elif field=='compensation': b['irreversible_actions']['compensation_receipt']=False
  elif field=='fence': b['fencing']['after_generation']=10
  else: b['limitations']=['pending external execution']
  bp=root/(field+'.json'); bp.write_text(json.dumps(b,sort_keys=True,separators=(',',':'))+'\n'); subprocess.run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(bp)+'.sig',str(bp)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try: v.verify(bp,pub,rev,pc,now,3600)
  except ValueError: pass
  else: raise AssertionError(field+' accepted')
 print('FAISAL_LIVE_DEPLOYMENT_VALIDATOR_TEST_OK positive_migration_fence_canary_rollback_compensation_and_denials')
if __name__=='__main__': main()
