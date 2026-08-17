#!/bin/sh
# Compare two FAISAL build outputs produced by separate build environments.
# Exact equality is required for release-grade reproducibility approval.
set -eu

A=${FAISAL_BUILD_A:-}
B=${FAISAL_BUILD_B:-}
REPORT=${FAISAL_REPRO_REPORT:-${A:-/tmp}/FAISAL-reproducibility-comparison.tsv}

fail() { echo "FAISAL_REPRO_COMPARE_FAIL:$*" >&2; exit 1; }
[ -n "$A" ] || fail "FAISAL_BUILD_A is required"
[ -n "$B" ] || fail "FAISAL_BUILD_B is required"
[ -r "$A/reproducible-build.env" ] || fail "missing metadata in build A"
[ -r "$B/reproducible-build.env" ] || fail "missing metadata in build B"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum unavailable"

read_env() {
  sed -n "s/^$1=//p" "$2" | head -1
}

source_a=$(read_env source_revision "$A/reproducible-build.env")
source_b=$(read_env source_revision "$B/reproducible-build.env")
epoch_a=$(read_env SOURCE_DATE_EPOCH "$A/reproducible-build.env")
epoch_b=$(read_env SOURCE_DATE_EPOCH "$B/reproducible-build.env")
config_a=$(read_env config_sha256 "$A/reproducible-build.env")
config_b=$(read_env config_sha256 "$B/reproducible-build.env")
[ -n "$source_a" ] && [ "$source_a" = "$source_b" ] || fail "source revision mismatch"
[ -n "$epoch_a" ] && [ "$epoch_a" = "$epoch_b" ] || fail "SOURCE_DATE_EPOCH mismatch"
[ -n "$config_a" ] && [ "$config_a" = "$config_b" ] || fail "configuration digest mismatch"

mkdir -p "$(dirname "$REPORT")"
{
  printf 'artifact\tstatus\tsha256_a\tsha256_b\n'
  printf 'source_revision\tpass\t%s\t%s\n' "$source_a" "$source_b"
  printf 'SOURCE_DATE_EPOCH\tpass\t%s\t%s\n' "$epoch_a" "$epoch_b"
  printf 'config_sha256\tpass\t%s\t%s\n' "$config_a" "$config_b"
} > "$REPORT"

for relative in arch/x86/boot/bzImage vmlinux modules.builtin .config; do
  file_a="$A/$relative"
  file_b="$B/$relative"
  [ -r "$file_a" ] || fail "missing build A artifact: $relative"
  [ -r "$file_b" ] || fail "missing build B artifact: $relative"
  hash_a=$(sha256sum "$file_a" | awk '{print $1}')
  hash_b=$(sha256sum "$file_b" | awk '{print $1}')
  if [ "$hash_a" != "$hash_b" ]; then
    printf '%s\tfail\t%s\t%s\n' "$relative" "$hash_a" "$hash_b" >> "$REPORT"
    fail "artifact mismatch: $relative"
  fi
  printf '%s\tpass\t%s\t%s\n' "$relative" "$hash_a" "$hash_b" >> "$REPORT"
done

printf 'FAISAL_INDEPENDENT_REPRODUCIBILITY_OK\nreport=%s\nsource_revision=%s\n' "$REPORT" "$source_a"
