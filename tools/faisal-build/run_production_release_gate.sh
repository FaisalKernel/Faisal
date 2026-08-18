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
PRODUCTION_CANDIDATE_MANIFEST=${FAISAL_PRODUCTION_CANDIDATE_MANIFEST:-}
CANDIDATE_PROVENANCE_MANIFEST=${FAISAL_CANDIDATE_PROVENANCE_MANIFEST:-}
CANDIDATE_EVIDENCE=${FAISAL_CANDIDATE_EVIDENCE:-}
PROGRAM_STATE=${FAISAL_PROGRAM_STATE:-$LINUX/FAISAL-PROGRAM-STATE.json}
ADVISORY_LEDGER=${FAISAL_ADVISORY_LEDGER:-}
CVE_OPERATIONS_EVIDENCE=${FAISAL_CVE_OPERATIONS_EVIDENCE:-}
CVE_OPERATIONS_PUBLIC_KEY=${FAISAL_CVE_OPERATIONS_PUBLIC_KEY:-$PUBLIC_KEY}
ACCELERATOR_EVIDENCE=${FAISAL_ACCELERATOR_EVIDENCE:-}
REPLICATION_EVIDENCE=${FAISAL_REPLICATION_EVIDENCE:-}
EXTERNAL_REPLICATION_EVIDENCE=${FAISAL_EXTERNAL_REPLICATION_EVIDENCE:-}
EXTERNAL_REPLICATION_PUBLIC_KEY=${FAISAL_EXTERNAL_REPLICATION_PUBLIC_KEY:-$PUBLIC_KEY}
EXTERNAL_REPLICATION_PACKAGE=${FAISAL_EXTERNAL_REPLICATION_PACKAGE:-}
DEPLOYMENT_EVIDENCE=${FAISAL_DEPLOYMENT_EVIDENCE:-}
LIVE_DEPLOYMENT_EVIDENCE=${FAISAL_LIVE_DEPLOYMENT_EVIDENCE:-}
LIVE_DEPLOYMENT_PUBLIC_KEY=${FAISAL_LIVE_DEPLOYMENT_PUBLIC_KEY:-$PUBLIC_KEY}
LIVE_DEPLOYMENT_PACKAGE=${FAISAL_LIVE_DEPLOYMENT_PACKAGE:-}
EXTERNAL_SECURITY_REVIEW=${FAISAL_EXTERNAL_SECURITY_REVIEW:-}
EXTERNAL_SECURITY_REVIEW_PACKAGE=${FAISAL_EXTERNAL_SECURITY_REVIEW_PACKAGE:-}
EXTERNAL_SECURITY_REVIEW_PUBLIC_KEY=${FAISAL_EXTERNAL_SECURITY_REVIEW_PUBLIC_KEY:-}
RELEASE_CANDIDATE_BUNDLE=${FAISAL_RELEASE_CANDIDATE_BUNDLE:-}
SIGNED_RELEASE_ATTESTATION=${FAISAL_SIGNED_RELEASE_ATTESTATION:-}
SIGNED_ATTESTATION_KEYRING=${FAISAL_SIGNED_ATTESTATION_KEYRING:-}
REQUIRE_SIGNED_RELEASE_ATTESTATION=${FAISAL_REQUIRE_SIGNED_RELEASE_ATTESTATION:-0}
REQUIRE_PRODUCTION_LINE=${FAISAL_REQUIRE_PRODUCTION_LINE:-1}
KERNEL_SOURCE=${FAISAL_KERNEL_SOURCE:-$LINUX}
REQUIRED_KERNEL_LINE=${FAISAL_REQUIRED_KERNEL_LINE:-}
EXPECTED_KERNEL_VERSION=${FAISAL_EXPECTED_KERNEL_VERSION:-}
LTS_SOAK_EVIDENCE=${FAISAL_LTS_SOAK_EVIDENCE:-}
RUN_ROLLBACK_QEMU=${FAISAL_RUN_ROLLBACK_QEMU:-0}
RUN_ADAPTER_CONFORMANCE=${FAISAL_RUN_ADAPTER_CONFORMANCE:-1}
SIGNING_OPERATIONAL_PROOF=${FAISAL_SIGNING_AUTHORITY_OPERATIONAL_PROOF:-}
SIGNING_ROOT_DISTRIBUTION=${FAISAL_SIGNING_AUTHORITY_ROOT_DISTRIBUTION:-$RELEASE_ROOT_DISTRIBUTION}
SIGNING_KEYRING=${FAISAL_SIGNING_AUTHORITY_KEYRING:-$RELEASE_KEYRING}
SIGNING_SOURCE_REVISION=${FAISAL_SIGNING_AUTHORITY_SOURCE_REVISION:-}
SIGNING_OPERATIONAL_REPORT=${FAISAL_SIGNING_AUTHORITY_REPORT:-${ARTIFACT_OUT:-/tmp}/FAISAL-signing-authority-operational.tsv}
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
[ -n "$SIGNING_OPERATIONAL_PROOF" ] || fail "FAISAL_SIGNING_AUTHORITY_OPERATIONAL_PROOF is required"
[ -r "$SIGNING_OPERATIONAL_PROOF" ] || fail "signing-authority operational proof is unreadable"
case "$SIGNING_OPERATIONAL_PROOF" in
  *.json) : ;;
  *) fail "structured JSON signing-authority operational proof is required" ;;
esac
[ -r "$SIGNING_ROOT_DISTRIBUTION" ] || fail "signing-authority root distribution is unreadable"
[ -r "$SIGNING_KEYRING" ] || fail "signing-authority keyring is unreadable"
[ -r "$SIGNING_KEYRING.sig" ] || fail "signing-authority keyring signature is missing"
[ -n "$SIGNING_SOURCE_REVISION" ] || fail "FAISAL_SIGNING_AUTHORITY_SOURCE_REVISION is required"
[ -n "$SECURITY_MANIFEST" ] || fail "FAISAL_SECURITY_MANIFEST is required"
[ -n "$PRODUCTION_CANDIDATE_MANIFEST" ] || fail "FAISAL_PRODUCTION_CANDIDATE_MANIFEST is required"
case "$PRODUCTION_CANDIDATE_MANIFEST" in
  *.json) : ;;
  *) fail "structured JSON production candidate manifest is required" ;;
esac
[ -r "$PRODUCTION_CANDIDATE_MANIFEST" ] || fail "production candidate manifest is unreadable"
if [ "$REQUIRE_PRODUCTION_LINE" = 1 ]; then
  [ -n "$CANDIDATE_PROVENANCE_MANIFEST" ] || fail "FAISAL_CANDIDATE_PROVENANCE_MANIFEST is required"
  [ -n "$CANDIDATE_EVIDENCE" ] || fail "FAISAL_CANDIDATE_EVIDENCE is required"
  [ -n "$PROGRAM_STATE" ] || fail "FAISAL_PROGRAM_STATE is required"
  [ -r "$CANDIDATE_PROVENANCE_MANIFEST" ] || fail "candidate provenance manifest is unreadable"
  [ -r "$CANDIDATE_EVIDENCE" ] || fail "candidate evidence is unreadable"
  [ -r "$PROGRAM_STATE" ] || fail "program state is unreadable"
fi
[ -n "$ADVISORY_LEDGER" ] || fail "FAISAL_ADVISORY_LEDGER is required"
[ -n "$CVE_OPERATIONS_EVIDENCE" ] || fail "FAISAL_CVE_OPERATIONS_EVIDENCE is required"
case "$CVE_OPERATIONS_EVIDENCE" in
  *.json) : ;;
  *) fail "structured JSON CVE operations evidence is required for production qualification" ;;
esac
[ -r "$CVE_OPERATIONS_EVIDENCE" ] || fail "CVE operations evidence is unreadable"
[ -r "$CVE_OPERATIONS_PUBLIC_KEY" ] || fail "CVE operations public key is unreadable"
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
[ -n "$EXTERNAL_REPLICATION_EVIDENCE" ] || fail "FAISAL_EXTERNAL_REPLICATION_EVIDENCE is required"
case "$EXTERNAL_REPLICATION_EVIDENCE" in
  *.json) : ;;
  *) fail "structured JSON external replication qualification evidence is required for production qualification" ;;
esac
[ -r "$EXTERNAL_REPLICATION_EVIDENCE" ] || fail "external replication qualification evidence is unreadable"
[ -n "$EXTERNAL_REPLICATION_PACKAGE" ] || fail "FAISAL_EXTERNAL_REPLICATION_PACKAGE is required"
[ -r "$EXTERNAL_REPLICATION_PACKAGE" ] || fail "external replication package manifest is unreadable"
[ -r "$EXTERNAL_REPLICATION_PUBLIC_KEY" ] || fail "external replication validation public key is unreadable"
case "$REPLICATION_EVIDENCE" in
  *.json) : ;;
  *) fail "structured JSON replication qualification evidence is required for production qualification" ;;
esac
[ -n "$LTS_SOAK_EVIDENCE" ] || fail "FAISAL_LTS_SOAK_EVIDENCE is required"
case "$LTS_SOAK_EVIDENCE" in
  *.json) : ;;
  *) fail "structured JSON LTS soak requalification evidence is required for production qualification" ;;
esac
[ -r "$LTS_SOAK_EVIDENCE" ] || fail "LTS soak requalification evidence is unreadable"
[ -n "$DEPLOYMENT_EVIDENCE" ] || fail "FAISAL_DEPLOYMENT_EVIDENCE is required"
[ -n "$LIVE_DEPLOYMENT_EVIDENCE" ] || fail "FAISAL_LIVE_DEPLOYMENT_EVIDENCE is required"
case "$LIVE_DEPLOYMENT_EVIDENCE" in
  *.json) : ;;
  *) fail "structured JSON live deployment qualification evidence is required for production qualification" ;;
esac
[ -r "$LIVE_DEPLOYMENT_EVIDENCE" ] || fail "live deployment qualification evidence is unreadable"
[ -n "$LIVE_DEPLOYMENT_PACKAGE" ] || fail "FAISAL_LIVE_DEPLOYMENT_PACKAGE is required"
[ -r "$LIVE_DEPLOYMENT_PACKAGE" ] || fail "live deployment qualification package is unreadable"
[ -r "$LIVE_DEPLOYMENT_PUBLIC_KEY" ] || fail "live deployment validation public key is unreadable"
case "$DEPLOYMENT_EVIDENCE" in
  *.json) : ;;
  *) fail "structured JSON deployment governance evidence is required for production qualification" ;;
esac
[ -n "$EXTERNAL_SECURITY_REVIEW" ] || fail "FAISAL_EXTERNAL_SECURITY_REVIEW is required"
case "$EXTERNAL_SECURITY_REVIEW" in
  *.json) : ;;
  *) fail "structured JSON independent external-security-review evidence is required for production qualification" ;;
esac
[ -n "$EXTERNAL_SECURITY_REVIEW_PACKAGE" ] || fail "FAISAL_EXTERNAL_SECURITY_REVIEW_PACKAGE is required"
[ -r "$EXTERNAL_SECURITY_REVIEW_PACKAGE" ] || fail "external security-review package manifest is unreadable"
case "$EXTERNAL_SECURITY_REVIEW_PACKAGE" in
  *.json) : ;;
  *) fail "exact external security-review package manifest must be JSON" ;;
esac
[ -n "$EXTERNAL_SECURITY_REVIEW_PUBLIC_KEY" ] || fail "FAISAL_EXTERNAL_SECURITY_REVIEW_PUBLIC_KEY is required"
[ -r "$EXTERNAL_SECURITY_REVIEW_PUBLIC_KEY" ] || fail "external reviewer public key is unreadable"
[ -x "$LINUX/tools/faisal-build/verify_industry_artifacts.sh" ] || fail "artifact verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_accelerator_qualification.sh" ] || fail "accelerator verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_replication_qualification.py" ] || fail "replication verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_external_replication_qualification.py" ] || fail "external replication verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_deployment_governance.py" ] || fail "deployment governance verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_lts_soak_requalification.py" ] || fail "LTS soak requalification verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_live_deployment_qualification.py" ] || fail "live deployment verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_external_security_review.py" ] || fail "external security-review verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_advisory_ledger.sh" ] || fail "advisory ledger verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_cve_operations.py" ] || fail "CVE operations verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_kernel_release_line.sh" ] || fail "kernel release-line verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_security_release_evidence.sh" ] || fail "security evidence verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_production_candidate_manifest.py" ] || fail "production candidate manifest verifier unavailable"
[ -x "$LINUX/tools/faisal-build/run_candidate_local_preflight.py" ] || fail "unified local candidate preflight unavailable"
[ -x "$LINUX/tools/faisal-build/verify_release_gate_report.py" ] || fail "release-gate report integrity verifier unavailable"
[ -r "$LINUX/tools/faisal-build/verify_release_attestation.py" ] || fail "signed release attestation verifier unavailable"
[ -r "$LINUX/tools/faisal-build/faisal_release_authority.py" ] || fail "release authority verifier unavailable"
[ -x "$LINUX/tools/faisal-build/verify_signing_authority_operational_proof.py" ] || fail "signing-authority operational-proof verifier unavailable"
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
FAISAL_PRODUCTION_CANDIDATE_MANIFEST="$PRODUCTION_CANDIDATE_MANIFEST" \
  python3 "$LINUX/tools/faisal-build/verify_production_candidate_manifest.py" >/tmp/faisal-release-candidate-manifest.log 2>&1 || {
  cat /tmp/faisal-release-candidate-manifest.log >&2
  fail "unified production candidate manifest verification"
}
printf 'production_candidate_manifest\tpass\t%s\n' "$PRODUCTION_CANDIDATE_MANIFEST" >> "$REPORT"
if [ "$REQUIRE_SIGNED_RELEASE_ATTESTATION" != 0 ] && [ "$REQUIRE_SIGNED_RELEASE_ATTESTATION" != 1 ]; then
  fail "invalid FAISAL_REQUIRE_SIGNED_RELEASE_ATTESTATION mode"
fi
if [ "$REQUIRE_SIGNED_RELEASE_ATTESTATION" = 1 ]; then
  [ -n "$RELEASE_CANDIDATE_BUNDLE" ] || fail "FAISAL_RELEASE_CANDIDATE_BUNDLE is required for signed attestation enforcement"
  [ -r "$RELEASE_CANDIDATE_BUNDLE/bundle.json" ] || fail "release candidate bundle is unreadable for signed attestation enforcement"
  [ -n "$SIGNED_RELEASE_ATTESTATION" ] || fail "FAISAL_SIGNED_RELEASE_ATTESTATION is required for production signed attestation enforcement"
  [ -r "$SIGNED_RELEASE_ATTESTATION" ] || fail "signed release attestation is unreadable"
  [ -n "$SIGNED_ATTESTATION_KEYRING" ] || fail "FAISAL_SIGNED_ATTESTATION_KEYRING is required for production signed attestation enforcement"
  [ -r "$SIGNED_ATTESTATION_KEYRING" ] || fail "signed attestation keyring is unreadable"
  python3 "$LINUX/tools/faisal-build/verify_release_attestation.py" \
    --repo "$LINUX" \
    --attestation "$SIGNED_RELEASE_ATTESTATION" \
    --trusted-keys "$SIGNED_ATTESTATION_KEYRING" \
    --candidate "$PRODUCTION_CANDIDATE_MANIFEST" \
    --provenance "$CANDIDATE_PROVENANCE_MANIFEST" \
    --bundle "$RELEASE_CANDIDATE_BUNDLE" \
    --require-production-approval >/tmp/faisal-release-signed-attestation.log 2>&1 || {
    cat /tmp/faisal-release-signed-attestation.log >&2
    fail "signed release attestation verification"
  }
  printf 'signed_release_attestation\tpass\t%s\n' "$SIGNED_RELEASE_ATTESTATION" >> "$REPORT"
else
  printf 'signed_release_attestation\tnot-enforced\tFAISAL_REQUIRE_SIGNED_RELEASE_ATTESTATION=0\n' >> "$REPORT"
fi

if [ "$REQUIRE_PRODUCTION_LINE" = 1 ]; then
  python3 "$LINUX/tools/faisal-build/run_candidate_local_preflight.py" \
    --repo "$LINUX" \
    --candidate "$PRODUCTION_CANDIDATE_MANIFEST" \
    --provenance "$CANDIDATE_PROVENANCE_MANIFEST" \
    --evidence "$CANDIDATE_EVIDENCE" \
    --state "$PROGRAM_STATE" >/tmp/faisal-release-local-preflight.log 2>&1 || {
    cat /tmp/faisal-release-local-preflight.log >&2
    fail "unified local candidate preflight"
  }
  grep -q 'FAISAL_LOCAL_PREFLIGHT_OK checks=5' /tmp/faisal-release-local-preflight.log ||
    fail "unified local candidate preflight marker missing"
  printf 'local_candidate_preflight\tpass\t%s\n' "$CANDIDATE_EVIDENCE" >> "$REPORT"
fi

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
FAISAL_LTS_SOAK_EVIDENCE="$LTS_SOAK_EVIDENCE" \
FAISAL_PUBLIC_KEY="$PUBLIC_KEY" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_LTS_SOAK_VERIFY_REPORT="${REPORT}.lts-soak.tsv" \
  python3 "$LINUX/tools/faisal-build/verify_lts_soak_requalification.py" >/tmp/faisal-release-lts-soak-gate.log 2>&1 || {
  cat /tmp/faisal-release-lts-soak-gate.log >&2
  fail "representative LTS soak requalification verification"
}
printf 'lts_soak_requalification\tpass\t%s\n' "$LTS_SOAK_EVIDENCE" >> "$REPORT"
[ -n "$expected_source_revision" ] || fail "build A source revision missing"
[ "$SIGNING_SOURCE_REVISION" = "$expected_source_revision" ] || fail "signing-authority proof source revision differs from build A"
python3 "$LINUX/tools/faisal-build/verify_signing_authority_operational_proof.py" \
  --proof "$SIGNING_OPERATIONAL_PROOF" \
  --root-distribution "$SIGNING_ROOT_DISTRIBUTION" \
  --keyring "$SIGNING_KEYRING" \
  --expected-source-revision "$expected_source_revision" \
  --report "$SIGNING_OPERATIONAL_REPORT" >/tmp/faisal-signing-authority-operational-gate.log 2>&1 || {
  cat /tmp/faisal-signing-authority-operational-gate.log >&2
  fail "signing-authority operational proof verification"
}
printf 'signing_authority_operational_proof\tpass\t%s\n' "$SIGNING_OPERATIONAL_REPORT" >> "$REPORT"
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
FAISAL_CVE_OPERATIONS_EVIDENCE="$CVE_OPERATIONS_EVIDENCE" \
FAISAL_CVE_OPERATIONS_PUBLIC_KEY="$CVE_OPERATIONS_PUBLIC_KEY" \
FAISAL_PUBLIC_KEY="$CVE_OPERATIONS_PUBLIC_KEY" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_CVE_OPERATIONS_VERIFY_REPORT="${REPORT}.cve-operations.tsv" \
  python3 "$LINUX/tools/faisal-build/verify_cve_operations.py" >/tmp/faisal-release-cve-operations-gate.log 2>&1 || {
  cat /tmp/faisal-release-cve-operations-gate.log >&2
  fail "operator-owned CVE operations verification"
}
printf 'cve_operations\tpass\t%s\n' "$CVE_OPERATIONS_EVIDENCE" >> "$REPORT"
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
FAISAL_EXTERNAL_REPLICATION_EVIDENCE="$EXTERNAL_REPLICATION_EVIDENCE" \
FAISAL_EXTERNAL_REPLICATION_PUBLIC_KEY="$EXTERNAL_REPLICATION_PUBLIC_KEY" \
FAISAL_EXTERNAL_REPLICATION_PACKAGE="$EXTERNAL_REPLICATION_PACKAGE" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_EXTERNAL_REPLICATION_VERIFY_REPORT="${REPORT}.external-replication.tsv" \
  python3 "$LINUX/tools/faisal-build/verify_external_replication_qualification.py" >/tmp/faisal-release-external-replication-gate.log 2>&1 || {
  cat /tmp/faisal-release-external-replication-gate.log >&2
  fail "external multi-host replication qualification verification"
}
printf 'external_replication_qualification\tpass\t%s\n' "$EXTERNAL_REPLICATION_EVIDENCE" >> "$REPORT"
FAISAL_DEPLOYMENT_EVIDENCE="$DEPLOYMENT_EVIDENCE" \
FAISAL_PUBLIC_KEY="$PUBLIC_KEY" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_DEPLOYMENT_VERIFY_REPORT="${REPORT}.deployment.tsv" \
  python3 "$LINUX/tools/faisal-build/verify_deployment_governance.py" >/tmp/faisal-release-deployment-gate.log 2>&1 || {
  cat /tmp/faisal-release-deployment-gate.log >&2
  fail "deployment governance verification"
}
printf 'deployment_governance\tpass\t%s\n' "$DEPLOYMENT_EVIDENCE" >> "$REPORT"
FAISAL_LIVE_DEPLOYMENT_EVIDENCE="$LIVE_DEPLOYMENT_EVIDENCE" \
FAISAL_LIVE_DEPLOYMENT_PUBLIC_KEY="$LIVE_DEPLOYMENT_PUBLIC_KEY" \
FAISAL_LIVE_DEPLOYMENT_PACKAGE="$LIVE_DEPLOYMENT_PACKAGE" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_LIVE_DEPLOYMENT_VERIFY_REPORT="${REPORT}.live-deployment.tsv" \
  python3 "$LINUX/tools/faisal-build/verify_live_deployment_qualification.py" >/tmp/faisal-release-live-deployment-gate.log 2>&1 || {
  cat /tmp/faisal-release-live-deployment-gate.log >&2
  fail "live multi-host deployment qualification verification"
}
printf 'live_deployment_qualification\tpass\t%s\n' "$LIVE_DEPLOYMENT_EVIDENCE" >> "$REPORT"
FAISAL_EXTERNAL_SECURITY_REVIEW="$EXTERNAL_SECURITY_REVIEW" \
FAISAL_EXTERNAL_SECURITY_REVIEW_PACKAGE="$EXTERNAL_SECURITY_REVIEW_PACKAGE" \
FAISAL_SECURITY_REVIEW_PUBLIC_KEY="$EXTERNAL_SECURITY_REVIEW_PUBLIC_KEY" \
FAISAL_EXPECTED_SOURCE_REV="$expected_source_revision" \
FAISAL_EXTERNAL_SECURITY_REVIEW_REPORT="${REPORT}.external-security-review.tsv" \
  python3 "$LINUX/tools/faisal-build/verify_external_security_review.py" >/tmp/faisal-release-external-security-review-gate.log 2>&1 || {
  cat /tmp/faisal-release-external-security-review-gate.log >&2
  fail "independent external security review verification"
}
printf 'external_security_review\tpass\t%s\n' "$EXTERNAL_SECURITY_REVIEW" >> "$REPORT"
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

printf 'report_integrity\tpass\t%s\n' "$REPORT" >> "$REPORT"
python3 "$LINUX/tools/faisal-build/verify_release_gate_report.py" --report "$REPORT" >/tmp/faisal-release-report-integrity.log 2>&1 || {
  cat /tmp/faisal-release-report-integrity.log >&2
  fail "release-gate report integrity"
}

printf 'FAISAL_PRODUCTION_RELEASE_GATE_OK\nreport=%s\n' "$REPORT"
