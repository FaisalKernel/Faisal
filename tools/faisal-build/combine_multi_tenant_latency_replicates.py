#!/usr/bin/env python3
import json
import statistics
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: combine_multi_tenant_latency_replicates.py A.json B.json OUT.json")
    inputs = [json.loads(Path(path).read_text()) for path in sys.argv[1:3]]
    by_level = {}
    for replica_index, summary in enumerate(inputs, 1):
        for row in summary["levels"]:
            by_level.setdefault(row["tenants"], []).append({
                "replica": replica_index,
                "iterations": row["iterations"],
                "avg_p50_ns": row["avg_p50_ns"],
                "max_p95_ns": row["max_p95_ns"],
                "max_p99_ns": row["max_p99_ns"],
                "aggregate_ops_s_x100": row["aggregate_ops_s_x100"],
                "wall_ns": row["wall_ns"],
                "failures": row["failures"],
            })
    levels = []
    for tenants, rows in sorted(by_level.items()):
        def spread(field):
            values = [row[field] for row in rows]
            return max(values) / min(values) if min(values) else None
        levels.append({
            "tenants": tenants,
            "replicas": rows,
            "median_avg_p50_ns": int(statistics.median(row["avg_p50_ns"] for row in rows)),
            "median_max_p95_ns": int(statistics.median(row["max_p95_ns"] for row in rows)),
            "median_max_p99_ns": int(statistics.median(row["max_p99_ns"] for row in rows)),
            "median_aggregate_ops_s_x100": int(statistics.median(row["aggregate_ops_s_x100"] for row in rows)),
            "p50_spread_ratio": spread("avg_p50_ns"),
            "p95_spread_ratio": spread("max_p95_ns"),
            "p99_spread_ratio": spread("max_p99_ns"),
            "variance_flag": spread("avg_p50_ns") > 10 or spread("max_p95_ns") > 10,
            "all_replicas_zero_failures": all(row["failures"] == 0 for row in rows),
        })
    output = {
        "replicas": [summary["source_log"] for summary in inputs],
        "levels": levels,
        "interpretation": {
            "measurements_are_qemu_tcg_only": True,
            "median_is_descriptive_not_a_hardware_performance_claim": True,
            "variance_flag_means_additional_repeated_runs_or_pinned_host_measurement_are_needed": True,
        },
    }
    Path(sys.argv[3]).write_text(json.dumps(output, indent=2) + "\n")
    for level in levels:
        print(
            "tenants={tenants} median_p50_ns={median_avg_p50_ns} "
            "median_p95_ns={median_max_p95_ns} median_p99_ns={median_max_p99_ns} "
            "median_ops_s_x100={median_aggregate_ops_s_x100} "
            "p50_spread={p50_spread_ratio:.3f} p95_spread={p95_spread_ratio:.3f} "
            "variance_flag={variance_flag}".format(**level)
        )


if __name__ == "__main__":
    main()
