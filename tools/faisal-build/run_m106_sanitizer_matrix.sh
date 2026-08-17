#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BASE="$ROOT/build/recovered"
M106_ROOT="${M106_ROOT:-$ROOT/build/m106-sanitizers}"
ITERATIONS="${M106_UAPI_FUZZ_ITERATIONS:-1024}"
SUMMARY="$M106_ROOT/m106-sanitizer-matrix.tsv"

rm -rf "$M106_ROOT"
mkdir -p "$M106_ROOT"
printf 'mode\tbuild\tconfig\tcompile\truntime\tdiagnostics\n' > "$SUMMARY"

build_mode() {
	mode=$1
	out="$M106_ROOT/$mode"
	log="$M106_ROOT/$mode-build.log"
	runlog="$M106_ROOT/$mode-runtime.log"
	mkdir -p "$out"
	cp "$BASE/.config" "$out/.config"
	make -C "$LINUX" O="$out" olddefconfig > "$log" 2>&1
	case "$mode" in
	kasan)
		"$LINUX/scripts/config" --file "$out/.config" \
			-e DEBUG_KERNEL -e SLUB_DEBUG -e CFS_BANDWIDTH -e CGROUP_SCHED \
				-e KASAN -e KASAN_GENERIC \
			-e KASAN_INLINE -e PROVE_LOCKING -e DEBUG_LOCK_ALLOC \
			-e LOCKDEP -e UBSAN -e KCOV
		;;
	kcsan)
		"$LINUX/scripts/config" --file "$out/.config" \
			-e DEBUG_KERNEL -e SLUB_DEBUG -e CFS_BANDWIDTH -e CGROUP_SCHED \
				-e KCSAN -e KCSAN_SELFTEST -e KCSAN_STRICT \
						-e SLUB_DEBUG -e PROVE_LOCKING -e DEBUG_LOCK_ALLOC \
			-e LOCKDEP -e UBSAN -e KCOV \
			-d SERIO_I8042 -d KEYBOARD_ATKBD -d SERIO -d INPUT_KEYBOARD
		;;
	*) echo "unknown sanitizer mode: $mode" >&2; exit 2 ;;
	esac
	make -C "$LINUX" O="$out" olddefconfig >> "$log" 2>&1
	make -C "$LINUX" O="$out" -j"${M106_JOBS:-$(nproc)}" bzImage >> "$log" 2>&1
	FAISAL_BUILD="$out" FAISAL_FUZZ_ROOTFS="$M106_ROOT/qemu-$mode" \
	FAISAL_UAPI_FUZZ_ITERATIONS="$ITERATIONS" \
	FAISAL_QEMU_SMP="${M106_QEMU_SMP:-1}" \
	FAISAL_QEMU_MEMORY="${M106_QEMU_MEMORY:-768M}" \
	FAISAL_QEMU_TIMEOUT_SECONDS="${M106_QEMU_TIMEOUT_SECONDS:-900}" \
		"$LINUX/tools/faisal-build/run_lifecycle_uapi_fuzz_qemu.sh" > "$runlog" 2>&1
	if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' \
		"$M106_ROOT/qemu-$mode/qemu.log"; then
		printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$mode" "$out" pass pass fail fault-marker >> "$SUMMARY"
		echo "M106_${mode}_DIAGNOSTIC_FAILURE" >&2
		return 1
	fi
	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$mode" "$out" pass pass pass clean >> "$SUMMARY"
}

build_mode kasan
build_mode kcsan
printf '%s\t%s\n' scope 'kcsan=headless;legacy-PS2-input-drivers-disabled' >> "$SUMMARY"

grep -q '^kasan' "$SUMMARY"
grep -q '^kcsan' "$SUMMARY"
printf '%s\n' 'M106_SANITIZER_MATRIX_QEMU_VALIDATION_OK'
cat "$SUMMARY"
