#!/usr/bin/env python3
from __future__ import annotations
import json,os,tempfile
from pathlib import Path
import verify_production_candidate_manifest as v
def main():
 root=Path('/home/ubuntu/agi-kernel'); repo=root/'linux'; build=root/'build/faisal-lts-6.18.44'; out=Path(tempfile.mkdtemp(prefix='faisal-candidate-test-'))/'candidate.json'; os.system(f'python3 {repo}/tools/faisal-build/prepare_production_candidate_manifest.py --repo {repo} --lts-build {build} --output {out} >/dev/null'); os.environ['FAISAL_PRODUCTION_CANDIDATE_MANIFEST']=str(out); v.main(); d=json.loads(out.read_text())
 for name,mutate in [('approved',lambda x:x['approval'].update(operator_approved=True,status='approved',authority='operator')),('hardware',lambda x:x['qualification_scope'].update(physical_hardware=True)),('missing_blocker',lambda x:x['release_blockers'].pop()),('tamper',lambda x:x['artifact'].update(bzImage_sha256='0'*64))]:
  bad=json.loads(out.read_text()); mutate(bad); q=out.parent/(name+'.json'); q.write_text(json.dumps(bad,sort_keys=True)+'\n'); os.environ['FAISAL_PRODUCTION_CANDIDATE_MANIFEST']=str(q)
  try: v.main()
  except (ValueError,SystemExit): pass
  else: raise AssertionError(name+' accepted')
 os.environ['FAISAL_PRODUCTION_CANDIDATE_MANIFEST']=str(out); print('FAISAL_PRODUCTION_CANDIDATE_VALIDATOR_TEST_OK exact_binding_truthful_boundary_and_denials')
if __name__=='__main__': main()
