#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ALLOWED_STATUSES = {'pass', 'not-enforced', 'not-run'}
KNOWN_CHECKS = {
    'operator_release_authority', 'signed_artifacts', 'production_candidate_manifest', 'production_readiness_boundary', 'local_candidate_preflight',
    'kernel_release_line', 'lts_soak_requalification', 'signing_authority_operational_proof', 'security_evidence',
    'advisory_ledger', 'cve_operations', 'accelerator_qualification', 'replication_qualification',
    'external_replication_qualification', 'external_qualification_intake', 'deployment_governance', 'live_deployment_qualification',
    'external_security_review', 'signed_release_attestation', 'adapter_conformance', 'independent_rebuild', 'rollback_qemu', 'report_integrity',
}

def fail(message: str) -> None:
    raise ValueError(message)

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--required-check', action='append', default=[])
    args = p.parse_args()
    report = args.report.resolve()
    if not report.is_file():
        fail('report is missing')
    rows = list(csv.reader(report.open(newline=''), delimiter='\t'))
    if not rows or rows[0] != ['check', 'status', 'detail']:
        fail('report header mismatch')
    seen = set()
    valid = set()
    for number, row in enumerate(rows[1:], 2):
        if len(row) != 3 or not all(cell.strip() for cell in row):
            fail(f'malformed row {number}')
        check, status, detail = (cell.strip() for cell in row)
        if check in seen:
            fail(f'duplicate check {check}')
        if status not in ALLOWED_STATUSES:
            fail(f'invalid status for {check}: {status}')
        if check not in KNOWN_CHECKS:
            fail(f'invalid check name {check}')
        seen.add(check)
        valid.add(check)
        if status == 'pass' and detail in {'', 'false', 'unknown'}:
            fail(f'pass row lacks trustworthy detail: {check}')
    missing = [name for name in args.required_check if name not in valid]
    if missing:
        fail('required checks missing: ' + ','.join(missing))
    if not valid:
        fail('report contains no checks')
    print(f'FAISAL_RELEASE_GATE_REPORT_OK checks={len(valid)}')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAISAL_RELEASE_GATE_REPORT_BLOCKED reason=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
