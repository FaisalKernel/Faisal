#!/bin/sh
# Verify accelerator qualification evidence without confusing QEMU validation
# with physical-device qualification.
set -eu

EVIDENCE=${FAISAL_ACCELERATOR_EVIDENCE:-}
PUBLIC_KEY=${FAISAL_PUBLIC_KEY:-}
EXPECTED_REV=${FAISAL_EXPECTED_SOURCE_REV:-}
REQUIRE_HARDWARE=${FAISAL_REQUIRE_ACCELERATOR_HARDWARE:-0}
REPORT=${FAISAL_ACCELERATOR_VERIFY_REPORT:-${EVIDENCE:-/tmp}/FAISAL-accelerator-verification.tsv}

# Physical production qualification uses the structured JSON evidence schema.
case "$EVIDENCE" in
  *.json)
    exec python3 "$(dirname "$0")/verify_physical_accelerator_qualification.py"
    ;;
esac

fail() { echo "FAISAL_ACCELERATOR_GATE_FAIL:$*" >&2; exit 1; }
[ -n "$EVIDENCE" ] || fail "FAISAL_ACCELERATOR_EVIDENCE is required"
[ -r "$EVIDENCE" ] || fail "accelerator evidence unreadable"
[ -r "$EVIDENCE.sig" ] || fail "accelerator evidence signature missing"
[ -n "$PUBLIC_KEY" ] || fail "FAISAL_PUBLIC_KEY is required"
[ -r "$PUBLIC_KEY" ] || fail "public key unreadable"
[ -n "$EXPECTED_REV" ] || fail "FAISAL_EXPECTED_SOURCE_REV is required"
[ "$REQUIRE_HARDWARE" = 0 ] || [ "$REQUIRE_HARDWARE" = 1 ] || fail "invalid hardware requirement"
openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$EVIDENCE.sig" "$EVIDENCE" >/dev/null 2>&1 ||
  fail "accelerator evidence signature mismatch"

value() { sed -n "s/^$1=//p" "$EVIDENCE" | head -1; }
source_revision=$(value source_revision)
mode=$(value qualification_mode)
status=$(value status)
backend=$(value backend)
devices=$(value devices)
isolation=$(value isolation)
accounting=$(value accounting)
sanitizer=$(value sanitizer)
evidence_digest=$(value evidence_sha256)

[ "$source_revision" = "$EXPECTED_REV" ] || fail "source revision mismatch"
[ "$status" = pass ] || fail "qualification status is not pass"
[ "$mode" = qemu ] || [ "$mode" = hardware ] || fail "invalid qualification mode"
[ -n "$backend" ] || fail "backend missing"
case "$devices" in ''|*[!0-9]*) fail "invalid device count";; esac
[ "$devices" -gt 0 ] || fail "no accelerator devices qualified"
[ "$isolation" = pass ] || fail "accelerator isolation evidence missing"
[ "$accounting" = pass ] || fail "accelerator accounting evidence missing"
[ "$sanitizer" = pass ] || fail "accelerator sanitizer evidence missing"
case "$evidence_digest" in [0-9a-fA-F][0-9a-fA-F]*) [ "${#evidence_digest}" -eq 64 ] || fail "invalid evidence digest" ;; *) fail "invalid evidence digest" ;; esac
if [ "$REQUIRE_HARDWARE" = 1 ] && [ "$mode" != hardware ]; then
  fail "physical hardware qualification required; mode=$mode"
fi

mkdir -p "$(dirname "$REPORT")"
{
  printf 'check\tstatus\tdetail\n'
  printf 'signature\tpass\tverified\n'
  printf 'source_revision\tpass\t%s\n' "$source_revision"
  printf 'qualification_mode\tpass\t%s\n' "$mode"
  printf 'backend\tpass\t%s\n' "$backend"
  printf 'devices\tpass\t%s\n' "$devices"
  printf 'isolation\tpass\t%s\n' "$isolation"
  printf 'accounting\tpass\t%s\n' "$accounting"
  printf 'sanitizer\tpass\t%s\n' "$sanitizer"
} > "$REPORT"
printf 'FAISAL_ACCELERATOR_QUALIFICATION_OK\nmode=%s\nbackend=%s\ndevices=%s\nreport=%s\n' "$mode" "$backend" "$devices" "$REPORT"
