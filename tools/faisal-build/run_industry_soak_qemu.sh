#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ITERATIONS=${FAISAL_SOAK_ITERATIONS:-16384}
ROUNDS=${FAISAL_SOAK_ROUNDS:-3}
OUT=${FAISAL_SOAK_OUT:-$ROOT/build/industry-soak}
SUMMARY="$OUT/summary.tsv"
mkdir -p "$OUT"
: > "$SUMMARY"

case "$ROUNDS" in ''|*[!0-9]*) echo 'ROUNDS must be numeric' >&2; exit 2;; esac
case "$ITERATIONS" in ''|*[!0-9]*) echo 'ITERATIONS must be numeric' >&2; exit 2;; esac
[ "$ROUNDS" -gt 0 ] && [ "$ROUNDS" -le 32 ] || { echo 'ROUNDS out of bounds' >&2; exit 2; }
[ "$ITERATIONS" -gt 0 ] && [ "$ITERATIONS" -le 1000000 ] || { echo 'ITERATIONS out of bounds' >&2; exit 2; }

for round in $(seq 1 "$ROUNDS"); do
  rootfs="$OUT/rootfs-$round"
  log="$OUT/qemu-$round.log"
  start=$(date +%s)
  FAISAL_BUILD="$BUILD" \
  FAISAL_FUZZ_ROOTFS="$rootfs" \
  FAISAL_UAPI_FUZZ_ITERATIONS="$ITERATIONS" \
    "$LINUX/tools/faisal-build/run_lifecycle_uapi_fuzz_qemu.sh" > "$OUT/runner-$round.log" 2>&1
  end=$(date +%s)
  cp "$rootfs/qemu.log" "$log"
  elapsed=$((end - start))
  if grep -aEq 'rcu: .*stall|BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|kernel BUG' "$log"; then
    printf '%s\t%s\t%s\t%s\n' "$round" "$ITERATIONS" "$elapsed" failed >> "$SUMMARY"
    echo "FAISAL_INDUSTRY_SOAK_DIAGNOSTIC round=$round" >&2
    exit 1
  fi
  printf '%s\t%s\t%s\t%s\n' "$round" "$ITERATIONS" "$elapsed" passed >> "$SUMMARY"
done

printf 'FAISAL_INDUSTRY_SOAK_OK rounds=%s iterations_per_round=%s total_iterations=%s summary=%s\n' \
  "$ROUNDS" "$ITERATIONS" "$((ROUNDS * ITERATIONS * 2))" "$SUMMARY"
