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
RELEASE_ROOT_DISTRIBUTION=${FAISAL_RELEASE_ROOT_DISTRIBUTION:-}
RELEASE_KEYRING=${FAISAL_RELEASE_KEYRING:-}
RELEASE_ATTESTATION=${FAISAL_RELEASE_ATTESTATION:-}
RELEASE_AUTHORITY_REPORT=${FAISAL_RELEASE_AUTHORITY_REPORT:-${ARTIFACT_OUT:-/tmp}/FAISAL-release-authority.tsv}
SECURITY_MANIFEST=${FAISAL_SECURITY_MANIFEST:-}
ADVISORY_LEDGER=${FAISAL_ADVISORY_LEDGER:-}
ACCELERATOR_EVIDENCE=${FAISAL_ACCELERATOR_EVIDENCE:-}
REPLICATION_EVIDENCE=${FAISAL_REPLICATION_EVIDENCE:-}
DEPLOYMENT_EVIDENCE=${FAISAL_DEPLOYMENT_EVIDENCE:-}
REQUIRE_PRODUCTION_LINE=${FAISAL_REQUIRE_PRODUCTION_LINE:-1}
KERNEL_SOURCE=${FAISAL_KERNEL_SOURCE:-$LINUX}
REQUIRED_KERNEL_LINE=${FAISAL_REQUIRED_KERNEL_LINE:-}
EXPECTED_KERNEL_VERSION=${FAISAL_EXPECTED_KERNEL_VERSION:-}
RUN_ROLLBACK_QEMU=${FAISAL_RUN_ROLLBACK_QEMU:-0}
RUN_ADAPTER_CONFORMANCE=${FAISAL_RUN_ADAPTER_CONFORMANCE:-1}
REPORT=${FAISAL_RELEASE_GATE_REPORT:-${ARTIFACT_OUT:-/tmp}/FAISAL-production-release-gate.tsv}

fail() { echo "FAISAL_RELEASE_GATE_FAIL:$*" >&2; exit 1; }
[ -n "$BUILD_A" ] || fail "FAISAL_BUILD_A is required"
[ -n "$BUILD_B" ] || fail "FAISAL_BUILD_B is required"
[ -n "$ARTIFACT_OUT" ] || fail "FAISAL_ARTIFACT_OUT is required"
[ -n "$PUBLIC_KEY" ] || fail "FAISAL_PUBLIC_KEY is required"
[ -r "$PUBLIC_KEY" ] || fail "public key is unreadable"
[ -n "$RELEASE_ROOT_DISTRIBUTION" ] || fail "FAISAL_RELEASE_ROOT_DISTRIBUTION is required"
[ -r "$RELEASE_ROOT_DISTRIBUTION" ] || fail "trusted root distribution is unreadable"
[ -n "$RELEASE_KEYRING" ] || fail "FAISAL_RELEASE_KEYRING is required"
[ -r "$RELEASE_KEYRING" ] || fail "trusted release keyring is unreadable"
[ -r "$RELEASE_KEYRING.sig" ] || fail "trusted release keyring signature is missing"
[ -n "$RELEASE_ATTESTATION" ] || fail "FAISAL_RELEASE_ATTESTATION is required"
[ -r "$RELEASE_ATTESTATION" ] || fail "release attestation is unreadable"
[ -r "$RELEASE_ATTESTATION.sig" ] || fail "release attestation signature is missing"
[ -n "$SECURITY_MANIFEST" ] || fail "FAISAL_SECURITY_MANIFEST is required"
[ -n "$ADVISORY_LEDGER" ] || fail "FAISAL_ADVISORY_LEDGER is required"
case "$ADVISORY_LEDGER" in
  *.json) : ;;
  *) fail "structured JSON advisory ledger is required for production qualification" ;;
esac
[ -n "$ACCELERATOR_EVIDENCE" ] || fail "FAISAL_ACCELERATOR_EVIDENCE is required"
case "$ACCELERATOR_EVIDENCE" in
  *.json) : ;;
  *) fail "structured JSON accelerator qualification evidence is required for production qualification" ;;
esac
[ -n "$REPLICATION_EVIDENCE" ] || fail "FAISAL_REPLICATION_EVIDENCE is required"
case "$REPLICATION_EVIDENCE" in
  *.json) : ;;
  *) fail "structured JSON replication qualification evidence is required for production qualification" ;;
esac
[ -n "$DEPLOYMENT_EVIDENCE" ] || fail "FAISAL_DEPLOYMENT_EVIDENCE is required"
case "$DEPLOYMENT_EVIDENCE" in
  *.json) : ;;
  *) fail "structured JSON deployment governance evidence is required for production qualification" ;;
esac
[ -x "$LINUX/tools/faisal-build/verify_industry_artifacts.sh" ] || fail "artifact verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_accelerator_qualification.sh" ] || fail "accelerator verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_replication_qualification.py" ] || fail "replication verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_deployment_governance.py" ] || fail "deployment governance verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_advisory_ledger.sh" ] || fail "advisory ledger verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_kernel_release_line.sh" ] || fail "kernel release-line verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_security_release_evidence.sh" ] || fail "security evidence verifier unavailable"
[ -r "$LINUX/tools/faisal-build/faisal_release_authority.py" ] || fail "release authority verifier unavailable"
[ -x "$LINUX/tools/faisal-build/compare_reproducible_builds.sh" ] || fail "reproducibility comparator unavailable"
[ "$RUN_ADAPTER_CONFORMANCE" = 0 ] || [ "$RUN_ADAPTER_CONFORMANCE" = 1 ] || fail "invalid adapter conformance mode"
[ "$RUN_ADAPTER_CONFORMANCE" = 0 ] || [ -x "$LINUX/tools/faisal-build/run_adapter_conformance_gate.sh" ] || fail "adapter conformance gate unavailable"

mkdir -p "$(dirname "$REPORT")"
printf 'check\tstatus\tdetail\n' > "$REPORT"

python3 "$LINUX/tools/faisal-build/faisal_release_authority.py" verify \
  --root-distribution "$RELEASE_ROOT_DISTRIBUTION" \
  --keyring "$RELEASE_KEYRING" \
  --attestation "$RELEASE_ATTESTATION" \
  --manifest "$ARTIFACT_OUT/FAISAL-build-manifest.json" \
  --sbom "$ARTIFACT_OUT/FAISAL-SBOM.spdx" \
  --checksums "$ARTIFACT_OUT/FAISAL-artifact-sha256sums.txt" \
  --report "$RELEASE_AUTHORITY_REPORT" >/tmp/faisal-release-authority-gate.log 2>&1 || {
  cat /tmp/faisal-release-authority-gate.log >&2
  fail "operator-controlled release authority verification"
}
printf 'operator_release_authority\tpass\t%s\n' "$RELEASE_AUTHORITY_REPORT" >> "$REPORT"

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

if [ "$REQUIRE_PRODUCTION_LINE" = 1 ]; then
  [ -n "$REQUIRED_KERNEL_LINE" ] || fail "FAISAL_REQUIRED_KERNEL_LINE is required for production release"
  [ -n "$EXPECTED_KERNEL_VERSION" ] || fail "FAISAL_EXPECTED_KERNEL_VERSION is required for production release"
  FAISAL_KERNEL_SOURCE="$KERNEL_SOURCE" \
  FAISAL_REQUIRED_KERNEL_LINE="$REQUIRED_KERNEL_LINE" \
  FAISAL_EXPECTED_KERNEL_VERSION="$EXPECTED_KERNEL_VERSION" \
  FAISAL_KERNEL_LINE_REPORT="${REPORT}.kernel-line.tsv" \
    "$LINUX/tools/faisal-build/verify_kernel_release_line.sh" >/tmp/faisal-release-kernel-line.log 2>&1 || {
    cat /tmp/faisal-release-kernel-line.log >&2
    fail "stable/LTS kernel release-line policy"
  }
  printf 'kernel_release_line\tpass\t%s:%s\n' "$REQUIRED_KERNEL_LINE" "$EXPECTED_KERNEL_VERSION" >> "$REPORT"
else
  printf 'kernel_release_line\tnot-enforced\tFAISAL_REQUIRE_PRODUCTION_LINE=0\n' >> "$REPORT"
fi

expected_source_revision=$(sed -n 's/^source_revision=//p' "$BUILD_A/reproducible-build.env" | head -1)
[ -n "$expected_source_revision" ] || fail "build A source revision missing"
FAISAL_SECURITY_MANIFEST="$SECURITY_MANIFEST" \
FAISAL_PUBLIC_KEY="$PUBLIC_KEY" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_SECURITY_VERIFY_REPORT="${REPORT}.security.tsv" \
  "$LINUX/tools/faisal-build/verify_security_release_evidence.sh" >/tmp/faisal-release-security-gate.log 2>&1 || {
  cat /tmp/faisal-release-security-gate.log >&2
  fail "security evidence verification"
}
printf 'security_evidence\tpass\t%s\n' "$SECURITY_MANIFEST" >> "$REPORT"
FAISAL_ADVISORY_LEDGER="$ADVISORY_LEDGER" \
FAISAL_PUBLIC_KEY="$PUBLIC_KEY" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_ADVISORY_VERIFY_REPORT="${REPORT}.advisory.tsv" \
  "$LINUX/tools/faisal-build/verify_advisory_ledger.sh" >/tmp/faisal-release-advisory-gate.log 2>&1 || {
  cat /tmp/faisal-release-advisory-gate.log >&2
  fail "advisory ledger verification"
}
printf 'advisory_ledger\tpass\t%s\n' "$ADVISORY_LEDGER" >> "$REPORT"
FAISAL_ACCELERATOR_EVIDENCE="$ACCELERATOR_EVIDENCE" \
FAISAL_PUBLIC_KEY="$PUBLIC_KEY" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_REQUIRE_ACCELERATOR_HARDWARE="$REQUIRE_PRODUCTION_LINE" \
FAISAL_ACCELERATOR_VERIFY_REPORT="${REPORT}.accelerator.tsv" \
  "$LINUX/tools/faisal-build/verify_accelerator_qualification.sh" >/tmp/faisal-release-accelerator-gate.log 2>&1 || {
  cat /tmp/faisal-release-accelerator-gate.log >&2
  fail "accelerator qualification verification"
}
printf 'accelerator_qualification\tpass\t%s\n' "$ACCELERATOR_EVIDENCE" >> "$REPORT"
FAISAL_REPLICATION_EVIDENCE="$REPLICATION_EVIDENCE" \
FAISAL_PUBLIC_KEY="$PUBLIC_KEY" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_REPLICATION_VERIFY_REPORT="${REPORT}.replication.tsv" \
  python3 "$LINUX/tools/faisal-build/verify_replication_qualification.py" >/tmp/faisal-release-replication-gate.log 2>&1 || {
  cat /tmp/faisal-release-replication-gate.log >&2
  fail "full TLS replication qualification verification"
}
printf 'replication_qualification\tpass\t%s\n' "$REPLICATION_EVIDENCE" >> "$REPORT"
FAISAL_DEPLOYMENT_EVIDENCE="$DEPLOYMENT_EVIDENCE" \
FAISAL_PUBLIC_KEY="$PUBLIC_KEY" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_DEPLOYMENT_VERIFY_REPORT="${REPORT}.deployment.tsv" \
  python3 "$LINUX/tools/faisal-build/verify_deployment_governance.py" >/tmp/faisal-release-deployment-gate.log 2>&1 || {
  cat /tmp/faisal-release-deployment-gate.log >&2
  fail "deployment governance verification"
}
printf 'deployment_governance\tpass\t%s\n' "$DEPLOYMENT_EVIDENCE" >> "$REPORT"
if [ "$RUN_ADAPTER_CONFORMANCE" = 1 ]; then
  FAISAL_BUILD="$BUILD_A" \
  FAISAL_ADAPTER_CONFORMANCE_REPORT="${REPORT}.adapter.tsv" \
    "$LINUX/tools/faisal-build/run_adapter_conformance_gate.sh" >/tmp/faisal-release-adapter-gate.log 2>&1 || {
    cat /tmp/faisal-release-adapter-gate.log >&2
    fail "adapter conformance verification"
  }
  printf 'adapter_conformance\tpass\t%s\n' "${REPORT}.adapter.tsv" >> "$REPORT"
else
  printf 'adapter_conformance\tnot-enforced\tFAISAL_RUN_ADAPTER_CONFORMANCE=0\n' >> "$REPORT"
fi

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
