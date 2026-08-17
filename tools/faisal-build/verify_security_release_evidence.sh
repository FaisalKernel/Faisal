#!/bin/sh
# Verify release security evidence. This validates evidence provenance and policy;
# it does not replace an independent security review or vulnerability scanner.
set -eu

MANIFEST=${FAISAL_SECURITY_MANIFEST:-}
PUBLIC_KEY=${FAISAL_PUBLIC_KEY:-}
EXPECTED_REV=${FAISAL_EXPECTED_SOURCE_REV:-}
MAX_AGE=${FAISAL_SECURITY_MAX_AGE_SECONDS:-604800}
REPORT=${FAISAL_SECURITY_VERIFY_REPORT:-${MANIFEST:-/tmp}/FAISAL-security-release-verification.tsv}

fail() { echo "FAISAL_SECURITY_GATE_FAIL:$*" >&2; exit 1; }
[ -n "$MANIFEST" ] || fail "FAISAL_SECURITY_MANIFEST is required"
[ -r "$MANIFEST" ] || fail "security manifest unreadable"
[ -n "$PUBLIC_KEY" ] || fail "FAISAL_PUBLIC_KEY is required"
[ -r "$PUBLIC_KEY" ] || fail "public key unreadable"
[ -r "$MANIFEST.sig" ] || fail "security manifest signature missing"
command -v openssl >/dev/null 2>&1 || fail "openssl unavailable"

openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$MANIFEST.sig" "$MANIFEST" >/dev/null 2>&1 ||
  fail "security manifest signature mismatch"

value() { sed -n "s/^$1=//p" "$MANIFEST" | head -1; }
source_revision=$(value source_revision)
scan_timestamp=$(value scan_timestamp_epoch)
scanner_status=$(value scanner_status)
sanitizer_status=$(value sanitizer_status)
critical=$(value critical_vulnerabilities)
high=$(value high_vulnerabilities)
advisory_status=$(value advisory_review_status)
evidence_digest=$(value evidence_sha256)

[ -n "$source_revision" ] || fail "source_revision missing"
[ -n "$scan_timestamp" ] || fail "scan_timestamp_epoch missing"
[ -n "$evidence_digest" ] || fail "evidence_sha256 missing"
[ -n "$EXPECTED_REV" ] && [ "$source_revision" = "$EXPECTED_REV" ] || [ -z "$EXPECTED_REV" ] || fail "source revision mismatch"
case "$scan_timestamp" in ''|*[!0-9]*) fail "invalid scan timestamp";; esac
case "$MAX_AGE" in ''|*[!0-9]*) fail "invalid maximum age";; esac
now=$(date +%s)
[ "$scan_timestamp" -le "$now" ] || fail "scan timestamp is in the future"
[ $((now - scan_timestamp)) -le "$MAX_AGE" ] || fail "security evidence is stale"
[ "$scanner_status" = pass ] || fail "scanner status is not pass"
[ "$sanitizer_status" = pass ] || fail "sanitizer status is not pass"
[ "$critical" = 0 ] || fail "critical vulnerabilities present"
[ "$high" = 0 ] || fail "high vulnerabilities present"
[ "$advisory_status" = pass ] || fail "upstream advisory review is not pass"

mkdir -p "$(dirname "$REPORT")"
{
  printf 'check\tstatus\tdetail\n'
  printf 'signature\tpass\tverified\n'
  printf 'source_revision\tpass\t%s\n' "$source_revision"
  printf 'freshness\tpass\t%s\n' "$scan_timestamp"
  printf 'scanner\tpass\tcritical=%s high=%s\n' "$critical" "$high"
  printf 'sanitizer\tpass\t%s\n' "$sanitizer_status"
  printf 'advisory_review\tpass\t%s\n' "$advisory_status"
  printf 'evidence_sha256\tpass\t%s\n' "$evidence_digest"
} > "$REPORT"
printf 'FAISAL_SECURITY_RELEASE_EVIDENCE_OK\nreport=%s\nsource_revision=%s\n' "$REPORT" "$source_revision"
