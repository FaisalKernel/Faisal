#!/usr/bin/env python3
from __future__ import annotations
import json,os,subprocess,tempfile,time
from pathlib import Path
import verify_lts_soak_requalification as v
def main():
 root=Path(tempfile.mkdtemp(prefix='faisal-lts-soak-test-')); key=root/'key.pem'; pub=root/'pub.pem'; subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(key)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); os.chmod(key,0o600); subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(pub)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 now=int(time.time()); d={'schema':v.SCHEMA,'status':'representative_lts_soak_requalified','source_revision':'candidate-1','recorded_epoch':now,'model_output_is_authority':False,'lts_source_revision':'105f2b85e4c26305a79f5e584df6ebb705858d33','bzimage_sha256':'8766f1019d80598c7982d91d89d7df27385a91ca7ea17d114d8869267204870b','config_sha256':'2c282274f1f716e2b1135b0a1fb819f99525dbe099ea0d31f1b3a2676f980e06','config':{'CONFIG_CFS_BANDWIDTH':'y'},'profiles':{'bounded_one_vcpu':{'result':'pass','qemu_acceleration':'tcg','qemu_smp':1,'qemu_acpi':'off','marker_driven_exit':True,'diagnostics':[],'rounds':2,'iterations_per_round':64,'summary_sha256':'a'*64},'representative_two_vcpu':{'result':'pass','qemu_acceleration':'tcg','qemu_smp':2,'qemu_acpi':'off','marker_driven_exit':True,'diagnostics':[],'rounds':3,'iterations_per_round':16384,'summary_sha256':'b'*64}},'rcu_stall_reproduction':{'old_profile_rejected':True,'mitigation':'qemu_pc_acpi_off_and_marker_driven_exit'},'kernel_diagnostics':[],'production_status':'representative_tcg_qualification_only'}
 report=root/'report.json'; report.write_text(json.dumps(d,sort_keys=True,separators=(',',':'))+'\n'); subprocess.run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(report)+'.sig',str(report)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); v.verify(report,pub,'candidate-1',now,3600)
 for name,mutate in [('diagnostic',lambda x:x.update(kernel_diagnostics=['rcu: rcu_preempt stall'])),('bad_profile',lambda x:x['profiles']['representative_two_vcpu'].update(qemu_acpi='on')),('low_threshold',lambda x:x['profiles']['representative_two_vcpu'].update(iterations_per_round=512)),('wrong_boundary',lambda x:x.update(production_status='production_qualified'))]:
  bad=json.loads(report.read_text()); mutate(bad); p=root/(name+'.json'); p.write_text(json.dumps(bad,sort_keys=True,separators=(',',':'))+'\n'); subprocess.run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(p)+'.sig',str(p)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try: v.verify(p,pub,'candidate-1',now,3600)
  except ValueError: pass
  else: raise AssertionError(name+' accepted')
 print('FAISAL_LTS_SOAK_VALIDATOR_TEST_OK exact_binding_profiles_rcu_mitigation_and_denials')
if __name__=='__main__': main()
