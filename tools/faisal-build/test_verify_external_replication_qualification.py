#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,subprocess,tempfile,time
from pathlib import Path
import verify_external_replication_qualification as v

def sha(p):
 d=hashlib.sha256(); d.update(Path(p).read_bytes()); return d.hexdigest()
def openssl(*a): subprocess.run(['openssl',*a],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def main():
 root=Path(tempfile.mkdtemp(prefix='faisal-external-repl-test-')); key=root/'key.pem'; pub=root/'pub.pem'; openssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(key)); os.chmod(key,0o600); openssl('pkey','-in',str(key),'-pubout','-out',str(pub))
 package=Path('/home/ubuntu/agi-kernel/build/m178-external-replication/qualification-package.json'); pkg=json.loads(package.read_text()); rev=pkg['source_revision']; package_copy=root/'qualification-package.json'; package_copy.write_bytes(package.read_bytes())
 markers=sorted(v.REQUIRED_MARKERS); report=root/'external.json'
 data={'schema':v.SCHEMA,'status':'external_multihost_production_qualified','source_revision':rev,'reviewed_epoch':int(time.time()),'model_output_is_authority':False,'qualification_package':{'package_id':pkg['package_id'],'manifest_sha256':sha(package_copy)},'candidate':{'protocol_sha256':'a'*64,'artifact_manifest_sha256':'b'*64,'build_id':'production-candidate-001'},'topology':{'node_count':3,'independent_hosts':True,'external_network':True,'nodes':[{'node_id':'replica-1','host_id':'host-a','endpoint':'10.24.1.11:50051','certificate_identity':'replica-1','certificate_serial':'1001','certificate_not_after_epoch':int(time.time())+86400},{'node_id':'replica-2','host_id':'host-b','endpoint':'10.24.1.12:50051','certificate_identity':'replica-2','certificate_serial':'1002','certificate_not_after_epoch':int(time.time())+86400},{'node_id':'replica-3','host_id':'host-c','endpoint':'10.24.1.13:50051','certificate_identity':'replica-3','certificate_serial':'1003','certificate_not_after_epoch':int(time.time())+86400}]},'production_pki':{'live':True,'ca_issuer':'prod-ca.example','trust_bundle_sha256':'c'*64,'revocation_check':True,'rotation_tested':True},'kms_or_vault':{'live':True,'provider':'vault_transit','key_id':'transit/fa-isal/replication:v3','sign_verify_receipt':'receipt-001','rotation_tested':True,'failure_denial_tested':True},'hardware_attestation':{'live':True,'provider':'tpm2','quote_verified':True,'key_non_exportability_verified':True},'deployment':{'orchestrator':'external-kubernetes-cluster','restart_tested':True,'rollback_tested':True,'persistent_state_verified':True},'markers':markers,'quorum':{'majority_commit_verified':True,'minority_commit_denied':True},'limitations':[]}
 payload=(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n').encode(); report.write_bytes(payload); subprocess.run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(report)+'.sig',str(report)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); v.verify(report,pub,rev,package_copy,int(time.time()),3600)
 for mutate in ('loopback','no-kms','pending'):
  bad=json.loads(report.read_text())
  if mutate=='loopback': bad['topology']['nodes'][0]['endpoint']='127.0.0.1:50051'
  elif mutate=='no-kms': bad['kms_or_vault']['live']=False
  else: bad['limitations']=['simulation pending']
  badp=root/(mutate+'.json'); badp.write_text(json.dumps(bad,sort_keys=True,separators=(',',':'))+'\n'); subprocess.run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(badp)+'.sig',str(badp)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try: v.verify(badp,pub,rev,package_copy,int(time.time()),3600)
  except ValueError: pass
  else: raise AssertionError(mutate+' accepted')
 print('FAISAL_EXTERNAL_REPLICATION_VALIDATOR_TEST_OK positive_three_host_and_loopback_kms_pending_denied')
if __name__=='__main__': main()
