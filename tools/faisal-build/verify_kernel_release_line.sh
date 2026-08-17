#!/bin/sh
# Enforce a production kernel release-line policy.
# Development release candidates are never production-approved implicitly.
set -eu

SOURCE_TREE=${FAISAL_KERNEL_SOURCE:-/home/ubuntu/agi-kernel/linux}
REQUIRED_LINE=${FAISAL_REQUIRED_KERNEL_LINE:-}
EXPECTED_VERSION=${FAISAL_EXPECTED_KERNEL_VERSION:-}
REPORT=${FAISAL_KERNEL_LINE_REPORT:-/tmp/FAISAL-kernel-release-line.tsv}

fail() { echo "FAISAL_KERNEL_LINE_GATE_FAIL:$*" >&2; exit 1; }
[ -d "$SOURCE_TREE" ] || fail "kernel source directory missing"
[ "$REQUIRED_LINE" = stable ] || [ "$REQUIRED_LINE" = lts ] || fail "required line must be stable or lts"
[ -n "$EXPECTED_VERSION" ] || fail "expected production kernel version is required"
command -v make >/dev/null 2>&1 || fail "make unavailable"

version=$(make -s -C "$SOURCE_TREE" kernelversion 2>/tmp/faisal-kernel-version.err) || {
  cat /tmp/faisal-kernel-version.err >&2
  fail "unable to determine kernel version"
}
[ "$version" = "$EXPECTED_VERSION" ] || fail "kernel version $version does not equal expected $EXPECTED_VERSION"
case "$version" in
  *-rc*|*-next*|*dirty*) fail "development or dirty kernel version is not production eligible" ;;
esac

case "$REQUIRED_LINE:$version" in
  stable:*) : ;;
  lts:*) : ;;
  *) fail "kernel version does not satisfy required $REQUIRED_LINE policy" ;;
esac

mkdir -p "$(dirname "$REPORT")"
{
  printf 'check\tstatus\tdetail\n'
  printf 'kernel_version\tpass\t%s\n' "$version"
  printf 'release_line\tpass\t%s\n' "$REQUIRED_LINE"
  printf 'development_suffix\tpass\tnone\n'
} > "$REPORT"
printf 'FAISAL_KERNEL_RELEASE_LINE_OK\nversion=%s\nline=%s\nreport=%s\n' "$version" "$REQUIRED_LINE" "$REPORT"
