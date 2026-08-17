#!/bin/sh
# Verify FAISAL production artifact metadata and detached signatures.
# A successful unsigned run is an integrity audit only, not a production release approval.
set -eu

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
OUT=${FAISAL_ARTIFACT_OUT:-$BUILD/industry-artifacts}
MANIFEST="$OUT/FAISAL-build-manifest.json"
SBOM="$OUT/FAISAL-SBOM.spdx"
CHECKSUMS="$OUT/FAISAL-artifact-sha256sums.txt"
REQUIRE_SIGNATURE=${FAISAL_REQUIRE_SIGNATURE:-0}
PUBLIC_KEY=${FAISAL_PUBLIC_KEY:-}
REPORT=${FAISAL_VERIFY_REPORT:-$OUT/FAISAL-release-verification.tsv}

fail() { echo "FAISAL_RELEASE_VERIFY_FAIL:$*" >&2; exit 1; }
[ -r "$MANIFEST" ] || fail "missing manifest"
[ -r "$SBOM" ] || fail "missing SBOM"
[ -r "$CHECKSUMS" ] || fail "missing checksums"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum unavailable"
command -v openssl >/dev/null 2>&1 || fail "openssl unavailable"

if grep -Eq '(^|[[:space:]])missing($|[[:space:]])' "$CHECKSUMS"; then
  fail "manifest contains missing artifact hash"
fi
sha256sum -c "$CHECKSUMS" >/dev/null || fail "artifact checksum mismatch"
grep -q '^SPDXVersion: SPDX-2\.[0-9]' "$SBOM" || fail "invalid SPDX header"
grep -q '"schema": "org.faisal.build-manifest.v1"' "$MANIFEST" || fail "invalid manifest schema"
grep -q '"source_revision":' "$MANIFEST" || fail "missing source revision"
grep -q '"config_sha256":' "$MANIFEST" || fail "missing config digest"

source_revision=$(sed -n 's/.*"source_revision": "\([0-9a-f][0-9a-f]*\)".*/\1/p' "$MANIFEST" | head -1)
case "$source_revision" in
  ''|*[!0-9a-f]*) fail "invalid source revision" ;;
esac
if [ -n "${FAISAL_EXPECTED_SOURCE_REV:-}" ] && [ "$source_revision" != "$FAISAL_EXPECTED_SOURCE_REV" ]; then
  fail "source revision mismatch"
fi

signature_status=unsigned
if [ "$REQUIRE_SIGNATURE" = 1 ]; then
  [ -n "$PUBLIC_KEY" ] || fail "FAISAL_PUBLIC_KEY required for production verification"
  [ -r "$PUBLIC_KEY" ] || fail "public key unreadable"
  for artifact in "$MANIFEST" "$SBOM" "$CHECKSUMS"; do
    [ -r "$artifact.sig" ] || fail "missing signature: $artifact.sig"
    openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$artifact.sig" "$artifact" >/dev/null 2>&1 ||
      fail "signature mismatch: $artifact"
  done
  signature_status=signed
fi

mkdir -p "$(dirname "$REPORT")"
{
  printf 'check\tstatus\tdetail\n'
  printf 'checksums\tpass\tverified\n'
  printf 'spdx\tpass\tSPDX-2.x\n'
  printf 'manifest\tpass\torg.faisal.build-manifest.v1\n'
  printf 'source_revision\tpass\t%s\n' "$source_revision"
  printf 'signatures\t%s\t%s\n' "$signature_status" "${PUBLIC_KEY:-not-required}"
} > "$REPORT"

if [ "$REQUIRE_SIGNATURE" = 1 ]; then
  printf 'FAISAL_PRODUCTION_ARTIFACT_VERIFICATION_OK\nreport=%s\nsignatures=signed\n' "$REPORT"
else
  printf 'FAISAL_ARTIFACT_INTEGRITY_VERIFICATION_OK\nreport=%s\nsignatures=unsigned-development-audit\n' "$REPORT"
fi
