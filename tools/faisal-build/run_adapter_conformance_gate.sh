#!/bin/sh
# Run the adapter conformance matrix against a booted FAISAL guest.
# This validates adapter behavior; it does not claim distributed hardware
# qualification or replace external service-provider conformance testing.
set -eu

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
REPORT=${FAISAL_ADAPTER_CONFORMANCE_REPORT:-$ROOT/build/adapter-conformance.tsv}

fail() { echo "FAISAL_ADAPTER_CONFORMANCE_FAIL:$*" >&2; exit 1; }
[ -d "$BUILD" ] || fail "build directory missing"

mkdir -p "$(dirname "$REPORT")"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
printf 'adapter\tstatus\tevidence\n' > "$TMP"

run_gate() {
	name=$1
	script=$2
	marker=$3
	log=${ROOT}/build/adapter-conformance-${name}.log
	if ! FAISAL_BUILD="$BUILD" "$LINUX/tools/faisal-build/$script" >"$log" 2>&1; then
		cat "$log" >&2
		fail "$name harness failed"
	fi
	grep -q "$marker" "$log" || fail "$name validation marker missing"
	printf '%s\tpass\t%s\n' "$name" "$marker" >> "$TMP"
}

run_gate sandbox run_adapter_sandbox_qemu.sh M100_SCOPE_TRAVERSAL_REJECTED_OK
run_gate nondeterministic run_nondeterministic_adapter_qemu.sh M102_NETWORK_SYSCALL_DENIED_OK
run_gate repository run_repository_adapter_qemu.sh M113_WORKSPACE_ROLLBACK_OK
run_gate scanner run_scanner_adapter_qemu.sh M114_VULNERABILITY_ADAPTER_FAIL_CLOSED_OK

mv "$TMP" "$REPORT"
printf 'FAISAL_ADAPTER_CONFORMANCE_QEMU_OK\nreport=%s\nadapters=4\n' "$REPORT"
