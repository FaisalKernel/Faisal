#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

REQUIRED_EVIDENCE = {
    'm204-production-candidate-consistency-validation.json',
    'm205-current-lts-provenance-consistency-validation.json',
    'm206-candidate-provenance-alignment-validation.json',
    'm207-candidate-evidence-freshness-validation.json',
    'm208-unified-local-candidate-preflight-validation.json',
    'm209-production-gate-local-preflight-validation.json',
    'm210-release-gate-report-integrity-validation.json',
    'm211-local-gate-summary-validation.json',
    'm212-local-gate-summary-reproducibility-validation.json',
    'm213-release-candidate-bundle-validation.json',
    'm214-release-candidate-archive-validation.json',
    'm215-release-attestation-validation.json',
    'm216-release-gate-attestation-integration-validation.json',
    'm217-external-qualification-intake-validation.json',
    'm218-external-qualification-gate-validation.json',
}

def fail(message):
    raise ValueError(message)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--repo',type=Path,required=True)
    p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--state',type=Path,required=True)
    a=p.parse_args(); repo=a.repo.resolve()
    candidate=json.loads(a.candidate.resolve().read_text()); state=json.loads(a.state.resolve().read_text())
    if candidate.get('status') != 'bounded_candidate_not_production_approved': fail('candidate is not explicitly bounded and unapproved')
    if state.get('current_tag','').startswith(('PRODUCTION-APPROVED','FAISAL-PRODUCTION')): fail('program state tag overstates production approval')
    forbidden={'production_approval':True,'external_evidence_complete':True,'approved':True,'production_approved':True}
    for key,value in forbidden.items():
        if candidate.get(key) is value: fail('candidate overstates '+key)
    evidence_dir=repo/'tools/faisal-build/evidence'
    missing=sorted(name for name in REQUIRED_EVIDENCE if not (evidence_dir/name).is_file())
    if missing: fail('required local evidence index is incomplete: '+','.join(missing))
    print('FAISAL_PRODUCTION_READINESS_BOUNDARY_OK checks=20 status=bounded_candidate_not_production_approved')

if __name__=='__main__':
    try: main()
    except Exception as exc:
        print('FAISAL_PRODUCTION_READINESS_BOUNDARY_BLOCKED reason='+str(exc),file=sys.stderr); raise SystemExit(1)
