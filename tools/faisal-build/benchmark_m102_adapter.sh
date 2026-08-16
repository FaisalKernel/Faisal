#!/bin/sh
set -eu
binary=${1:-/home/ubuntu/agi-kernel/build/m102/agi_nondeterministic_adapter_test}
out=${2:-/home/ubuntu/agi-kernel/build/m102/benchmark-host.csv}
mkdir -p "$(dirname "$out")"
printf 'trial,seconds,rc\n' > "$out"
trial=1
while [ "$trial" -le 10 ]; do
	start_ns=$(date +%s%N)
	set +e
	"$binary" >/tmp/m102-benchmark-run.log 2>&1
	rc=$?
	set -e
	end_ns=$(date +%s%N)
	seconds=$(awk -v start="$start_ns" -v end="$end_ns" 'BEGIN { printf "%.6f", (end-start)/1000000000 }')
printf '%s,%s,%s\n' "$trial" "$seconds" "$rc" >> "$out"
	[ "$rc" -eq 0 ]
	trial=$((trial + 1))
done
