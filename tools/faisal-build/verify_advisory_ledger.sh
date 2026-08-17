#!/bin/sh
# Verify a signed, source-bound upstream advisory ledger for production release.
set -eu

LEDGER=${FAISAL_ADVISORY_LEDGER:-}
PUBLIC_KEY=${FAISAL_PUBLIC_KEY:-}
EXPECTED_REV=${FAISAL_EXPECTED_SOURCE_REV:-}
MAX_AGE=${FAISAL_ADVISORY_MAX_AGE_SECONDS:-2592000}
REPORT=${FAISAL_ADVISORY_VERIFY_REPORT:-${LEDGER:-/tmp}/FAISAL-advisory-verification.tsv}

fail() { echo "FAISAL_ADVISORY_GATE_FAIL:$*" >&2; exit 1; }
[ -n "$LEDGER" ] || fail "FAISAL_ADVISORY_LEDGER is required"
[ -r "$LEDGER" ] || fail "advisory ledger unreadable"
[ -r "$LEDGER.sig" ] || fail "advisory ledger signature missing"
[ -n "$PUBLIC_KEY" ] || fail "FAISAL_PUBLIC_KEY is required"
[ -r "$PUBLIC_KEY" ] || fail "public key unreadable"
[ -n "$EXPECTED_REV" ] || fail "FAISAL_EXPECTED_SOURCE_REV is required"
case "$MAX_AGE" in ''|*[!0-9]*) fail "invalid maximum age";; esac
openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$LEDGER.sig" "$LEDGER" >/dev/null 2>&1 ||
  fail "advisory ledger signature mismatch"

header=$(head -1 "$LEDGER")
[ "$header" = 'cve_id	status	source_revision	evidence_sha256	reviewed_epoch' ] ||
  fail "invalid advisory ledger header"
now=$(date +%s)
TAB=$(printf '\t')
rows=0
seen=/tmp/faisal-advisory-seen.$$
rows_file=/tmp/faisal-advisory-rows.$$
trap 'rm -f "$seen" "$rows_file"' EXIT
: > "$seen"
tail -n +2 "$LEDGER" > "$rows_file"
{
  printf 'check\tstatus\tdetail\n'
  printf 'signature\tpass\tverified\n'
} > "$REPORT"

while IFS="$TAB" read -r cve status revision digest reviewed extra; do
  [ -n "$cve" ] || continue
  [ -z "${extra:-}" ] || fail "extra advisory fields for $cve"
  case "$cve" in CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*) : ;; *) fail "invalid CVE identifier $cve";; esac
  case "$status" in fixed|not_affected|mitigated) : ;; *) fail "unresolved advisory $cve status=$status";; esac
  [ "$revision" = "$EXPECTED_REV" ] || fail "source revision mismatch for $cve"
  case "$digest" in [0-9a-fA-F][0-9a-fA-F]*) [ "${#digest}" -eq 64 ] || fail "invalid evidence digest for $cve" ;; *) fail "invalid evidence digest for $cve" ;; esac
  case "$reviewed" in ''|*[!0-9]*) fail "invalid review timestamp for $cve";; esac
  [ "$reviewed" -le "$now" ] || fail "future review timestamp for $cve"
  [ $((now - reviewed)) -le "$MAX_AGE" ] || fail "stale advisory review for $cve"
  grep -qx "$cve" "$seen" && fail "duplicate advisory $cve"
  printf '%s\n' "$cve" >> "$seen"
  rows=$((rows + 1))
  printf 'advisory\tpass\t%s:%s\n' "$cve" "$status" >> "$REPORT"
done < "$rows_file"

[ "$rows" -gt 0 ] || fail "advisory ledger contains no records"
printf 'FAISAL_ADVISORY_LEDGER_OK\nrows=%s\nreport=%s\n' "$rows" "$REPORT"
