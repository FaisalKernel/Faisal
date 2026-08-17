#!/usr/bin/env python3
import csv
import json
import re
import sys
from pathlib import Path

TENANT_RE = re.compile(
    r"FAISAL_MT_TENANT_LATENCY tenant=(?P<tenant>\d+) iterations=(?P<iterations>\d+) "
    r"elapsed_ns=(?P<elapsed_ns>\d+) min_ns=(?P<min_ns>\d+) p50_ns=(?P<p50_ns>\d+) "
    r"p95_ns=(?P<p95_ns>\d+) "

    r"p99_ns=(?P<p99_ns>\d+) max_ns=(?P<max_ns>\d+) failures=(?P<failures>\d+)"
)
LEVEL_RE = re.compile(
    r"FAISAL_MT_LEVEL_OK tenants=(?P<tenants>\d+) iterations=(?P<iterations>\d+) "
    r"batch=(?P<batch>\d+) aggregate_ops=(?P<aggregate_ops>\d+) "
    r"wall_ns=(?P<wall_ns>\d+) aggregate_ops_s_x100=(?P<aggregate_ops_s_x100>\d+) "
    r"avg_p50_ns=(?P<avg_p50_ns>\d+) "
    r"max_p95_ns=(?P<max_p95_ns>\d+) max_p99_ns=(?P<max_p99_ns>\d+) "
    r"max_ns=(?P<max_ns>\d+) failures=(?P<failures>\d+)"
)


def parse(path: Path):
    tenant_rows = []
    level_rows = []
    for line in path.read_text().splitlines():
        match = TENANT_RE.search(line)
        if match:
            row = {key: int(value) for key, value in match.groupdict().items()}
            tenant_rows.append(row)
        match = LEVEL_RE.search(line)
        if match:
            row = {key: int(value) for key, value in match.groupdict().items()}
            level_rows.append(row)
    if not tenant_rows or not level_rows:
        raise SystemExit("benchmark log did not contain complete tenant and level markers")
    baseline = next((row for row in level_rows if row["tenants"] == 1), None)
    if baseline is None:
        raise SystemExit("missing one-tenant baseline")
    baseline_p50 = baseline["avg_p50_ns"]
    baseline_p95 = baseline["max_p95_ns"]
    baseline_p99 = baseline["max_p99_ns"]
    for row in level_rows:
        row["p50_ratio_vs_one_tenant"] = (
            row["avg_p50_ns"] / baseline_p50 if baseline_p50 else None
        )
        row["p95_ratio_vs_one_tenant"] = (
            row["max_p95_ns"] / baseline_p95 if baseline_p95 else None
        )
        row["p99_ratio_vs_one_tenant"] = (
            row["max_p99_ns"] / baseline_p99 if baseline_p99 else None
        )
    summary = {
        "source_log": str(path),
        "baseline": baseline,
        "levels": level_rows,
        "tenant_samples": tenant_rows,
        "interpretation": {
            "baseline_is_one_tenant_same_qemu_run": True,
            "ratios_are_controlled_qemu_measurements": True,
            "physical_hardware_claim": False,
            "tail_latency_can_include_qemu_tcg_scheduling_and_guest_contention": True,
        },
    }
    return tenant_rows, level_rows, summary


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: analyze_multi_tenant_latency.py LOG OUT_JSON OUT_CSV")
    log_path, json_path, csv_path = map(Path, sys.argv[1:])
    tenant_rows, level_rows, summary = parse(log_path)
    Path(json_path).write_text(json.dumps(summary, indent=2) + "\n")
    fields = [
        "tenants", "iterations", "batch", "aggregate_ops", "wall_ns", "aggregate_ops_s_x100",
        "avg_p50_ns", "max_p95_ns", "max_p99_ns", "max_ns", "failures",
        "p50_ratio_vs_one_tenant", "p95_ratio_vs_one_tenant", "p99_ratio_vs_one_tenant",
    ]
    with Path(csv_path).open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(level_rows)
    for row in level_rows:
        print(
            "tenants={tenants} avg_p50_ns={avg_p50_ns} max_p95_ns={max_p95_ns} "
            "max_p99_ns={max_p99_ns} aggregate_ops_s_x100={aggregate_ops_s_x100} "
            "p50_ratio={p50_ratio_vs_one_tenant:.3f}".format(**row)
        )


if __name__ == "__main__":
    main()
