#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED = {
    'CONFIG_PREEMPT_RT': 'y',
    'CONFIG_PREEMPTION': 'y',
    'CONFIG_HIGH_RES_TIMERS': 'y',
    'CONFIG_RT_MUTEXES': 'y',
    'CONFIG_CPU_ISOLATION': 'y',
    'CONFIG_HZ': '1000',
}
OPTIONAL = {
    'CONFIG_NO_HZ_FULL': 'y',
    'CONFIG_RCU_NOCB_CPU': 'y',
    'CONFIG_IRQ_FORCED_THREADING': 'y',
}


def parse_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        values[key] = value.strip().strip('"')
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    config = args.config.resolve()
    if not config.is_file():
        raise SystemExit(f'missing config: {config}')
    values = parse_config(config)
    missing = {key: expected for key, expected in REQUIRED.items()
               if values.get(key) != expected}
    optional_missing = {key: expected for key, expected in OPTIONAL.items()
                        if values.get(key) != expected}
    result = {
        'schema': 'org.faisal.rt-profile.v1',
        'config': str(config),
        'required': REQUIRED,
        'optional': OPTIONAL,
        'missing_required': missing,
        'missing_optional': optional_missing,
        'status': 'qualified_profile' if not missing else 'blocked_not_preempt_rt',
        'production_approval': False,
        'hard_latency_claim': False,
        'physical_hardware_qualification': False,
        'model_output_is_authority': False,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"FRT_PROFILE_STATUS={result['status']}")
        print(f"FRT_PROFILE_REQUIRED_MISSING={','.join(sorted(missing)) or 'none'}")
        print(f"FRT_PROFILE_OPTIONAL_MISSING={','.join(sorted(optional_missing)) or 'none'}")
        print('FRT_PROFILE_PRODUCTION_APPROVAL=0')
        print('FRT_PROFILE_HARD_LATENCY_CLAIM=0')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
