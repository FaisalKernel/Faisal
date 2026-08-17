#!/bin/sh
set -eu

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
BUILD=${FAISAL_BUILD:-$ROOT/build/m156-backpressure}
AUTH="$LINUX/tools/faisal-build/faisal_release_authority.py"
WORK=$(mktemp -d /tmp/faisal-release-artifacts.XXXXXX)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

mkdir -p "$WORK/artifacts"
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/root-private.pem" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/release-private.pem" >/dev/null 2>&1
FAISAL_ROOT="$ROOT" FAISAL_LINUX="$LINUX" FAISAL_BUILD="$BUILD" \
  FAISAL_ARTIFACT_OUT="$WORK/artifacts" \
  "$LINUX/tools/faisal-build/generate_industry_artifacts.sh" >/tmp/faisal-release-artifact-generation.log 2>&1
python3 "$AUTH" create-keyring \
  --root-private-key "$WORK/root-private.pem" \
  --release-private-key "$WORK/release-private.pem" \
  --keyring "$WORK/trusted-keyring.json" \
  --root-distribution "$WORK/trusted-root.json" >/tmp/faisal-release-keyring.log
cat > "$WORK/operator-approval.json" <<EOF
{
  "schema": "org.faisal.operator-approval.v1",
  "approved": true,
  "approval_id": "test-artifact-approval-001",
  "approved_by": "FAISAL-test-operator",
  "scope": "FAISAL-production-release",
  "expires_epoch": $(( $(date +%s) + 3600 ))
}
EOF
python3 "$AUTH" sign \
  --release-private-key "$WORK/release-private.pem" \
  --keyring "$WORK/trusted-keyring.json" \
  --operator-approval "$WORK/operator-approval.json" \
  --release-id "test-artifact-release-001" \
  --manifest "$WORK/artifacts/FAISAL-build-manifest.json" \
  --sbom "$WORK/artifacts/FAISAL-SBOM.spdx" \
  --checksums "$WORK/artifacts/FAISAL-artifact-sha256sums.txt" \
  --attestation "$WORK/release-attestation.json" >/tmp/faisal-release-attestation.log
python3 "$AUTH" verify \
  --root-distribution "$WORK/trusted-root.json" \
  --keyring "$WORK/trusted-keyring.json" \
  --attestation "$WORK/release-attestation.json" \
  --manifest "$WORK/artifacts/FAISAL-build-manifest.json" \
  --sbom "$WORK/artifacts/FAISAL-SBOM.spdx" \
  --checksums "$WORK/artifacts/FAISAL-artifact-sha256sums.txt" \
  --report "$WORK/release-authority.tsv" >/tmp/faisal-release-verification.log
cp "$WORK/release-authority.tsv" "$ROOT/build/faisal-release-authority-artifact-verification.tsv"
printf '\n# tamper rejection\n' >> "$WORK/artifacts/FAISAL-SBOM.spdx"
if python3 "$AUTH" verify \
  --root-distribution "$WORK/trusted-root.json" \
  --keyring "$WORK/trusted-keyring.json" \
  --attestation "$WORK/release-attestation.json" \
  --manifest "$WORK/artifacts/FAISAL-build-manifest.json" \
  --sbom "$WORK/artifacts/FAISAL-SBOM.spdx" \
  --checksums "$WORK/artifacts/FAISAL-artifact-sha256sums.txt" \
  --report "$WORK/tampered.tsv" >/tmp/faisal-release-tamper.log 2>&1; then
  echo 'FAISAL_RELEASE_ARTIFACT_TAMPER_UNEXPECTED_PASS' >&2
  exit 1
fi
printf 'FAISAL_RELEASE_ARTIFACT_AUTHORITY_E2E_OK valid_generation_sign_verify_tamper_denial=pass\n'
