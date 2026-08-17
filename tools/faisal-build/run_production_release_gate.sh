#!/bin/sh
# FAISAL production release gate.
# This gate approves only evidence-backed artifacts; model output cannot satisfy it.
set -eu

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
BUILD_A=${FAISAL_BUILD_A:-}
BUILD_B=${FAISAL_BUILD_B:-}
ARTIFACT_OUT=${FAISAL_ARTIFACT_OUT:-}
PUBLIC_KEY=${FAISAL_PUBLIC_KEY:-}
RUN_ROLLBACK_QEMU=${FAISAL_RUN_ROLLBACK_QEMU:-0}
REPORT=${FAISAL_RELEASE_GATE_REPORT:-${ARTIFACT_OUT:-/tmp}/FAISAL-production-release-gate.tsv}

fail() { echo "FAISAL_RELEASE_GATE_FAIL:$*" >&2; exit 1; }
[ -n "$BUILD_A" ] || fail "FAISAL_BUILD_A is required"
[ -n "$BUILD_B" ] || fail "FAISAL_BUILD_B is required"
[ -n "$ARTIFACT_OUT" ] || fail "FAISAL_ARTIFACT_OUT is required"
[ -n "$PUBLIC_KEY" ] || fail "FAISAL_PUBLIC_KEY is required"
[ -r "$PUBLIC_KEY" ] || fail "public key is unreadable"
[ -x "$LINUX/tools/faisal-build/verify_industry_artifacts.sh" ] || fail "artifact verifier unavailable"
[ -x "$LINUX/tools/faisal-build/compare_reproducible_builds.sh" ] || fail "reproducibility comparator unavailable"

mkdir -p "$(dirname "$REPORT")"
printf 'check\tstatus\tdetail\n' > "$REPORT"

FAISAL_BUILD="$BUILD_A" \
FAISAL_ARTIFACT_OUT="$ARTIFACT_OUT" \
FAISAL_REQUIRE_SIGNATURE=1 \
FAISAL_PUBLIC_KEY="$PUBLIC_KEY" \
FAISAL_VERIFY_REPORT="${REPORT}.artifacts.tsv" \
  "$LINUX/tools/faisal-build/verify_industry_artifacts.sh" >/tmp/faisal-release-artifact-gate.log 2>&1 || {
  cat /tmp/faisal-release-artifact-gate.log >&2
  fail "signed artifact verification"
}
printf 'signed_artifacts\tpass\t%s\n' "$ARTIFACT_OUT" >> "$REPORT"

FAISAL_BUILD_A="$BUILD_A" \
FAISAL_BUILD_B="$BUILD_B" \
FAISAL_REPRO_REPORT="${REPORT}.repro.tsv" \
  "$LINUX/tools/faisal-build/compare_reproducible_builds.sh" >/tmp/faisal-release-repro-gate.log 2>&1 || {
  cat /tmp/faisal-release-repro-gate.log >&2
  fail "independent reproducibility comparison"
}
printf 'independent_rebuild\tpass\t%s==%s\n' "$BUILD_A" "$BUILD_B" >> "$REPORT"

if [ "$RUN_ROLLBACK_QEMU" = 1 ]; then
  [ -r "$BUILD_A/arch/x86/boot/bzImage" ] || fail "rollback kernel image missing"
  FAISAL_BUILD="$BUILD_A" "$LINUX/tools/faisal-build/run_autonomy_control_qemu.sh" \
    >/tmp/faisal-release-rollback-gate.log 2>&1 || {
    cat /tmp/faisal-release-rollback-gate.log >&2
    fail "booted rollback validation"
  }
  grep -q 'M104_AUTONOMY_CONTROL_QEMU_VALIDATION_OK' /tmp/faisal-release-rollback-gate.log ||
    fail "rollback marker missing"
  printf 'rollback_qemu\tpass\tapproval-canary-rollback-replay\n' >> "$REPORT"
else
  printf 'rollback_qemu\tnot-run\tFAISAL_RUN_ROLLBACK_QEMU=1 required\n' >> "$REPORT"
fi

printf 'FAISAL_PRODUCTION_RELEASE_GATE_OK\nreport=%s\n' "$REPORT"
