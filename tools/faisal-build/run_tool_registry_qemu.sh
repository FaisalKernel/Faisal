#!/bin/sh
set -eu

OUT=${BUILD:-/home/ubuntu/agi-kernel/build/recovered}
ROOT=${ROOTFS:-/home/ubuntu/agi-kernel/build/qemu-faisal-m99-tools/rootfs}
IMAGE=${IMAGE:-/home/ubuntu/agi-kernel/build/qemu-faisal-m99-tools/initramfs.cpio.gz}
LOG=${LOG:-/home/ubuntu/agi-kernel/build/qemu-faisal-m99-tools/qemu.log}
SELFTEST=${SELFTEST:-/home/ubuntu/agi-kernel/build/recovered/agi_tool_registry_test}
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/tmp"
cp "$(command -v busybox)" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
ln -sf busybox "$ROOT/bin/mknod"
cp "$SELFTEST" "$ROOT/bin/agi_tool_registry_test"
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
if [ -r /sys/class/misc/agi_lifecycle/dev ]; then
  dev=$(cat /sys/class/misc/agi_lifecycle/dev)
  major=${dev%:*}
  minor=${dev#*:}
  mknod /dev/agi_lifecycle c "$major" "$minor" 2>/dev/null || true
fi
if [ ! -e /dev/agi_lifecycle ]; then
  printf 'FAISAL_M99_DEVICE_NODE_MISSING\n'
  printf 'FAISAL_M99_TEST_RC=1\n'
  poweroff -f
fi
printf 'FAISAL_M99_BOOT_OK\n'
/bin/agi_tool_registry_test --require-kernel
rc=$?
printf 'FAISAL_M99_TEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOT/init"
mkdir -p "$(dirname "$IMAGE")" "$(dirname "$LOG")"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$IMAGE")
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 \
	-m 512M -smp "${QEMU_SMP:-1}" -kernel "$OUT/arch/x86/boot/bzImage" \
	-initrd "$IMAGE" -append 'console=ttyS0 rdinit=/init quiet' \
	-nographic -no-reboot -monitor none -serial "file:$LOG" \
	>/tmp/faisal-m99-tools-qemu-stderr.log 2>&1
rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m99-tools-qemu-stderr.log 2>/dev/null || true
printf 'QEMU_RC=%s\n' "$rc"
[ "$rc" -eq 0 ]
for marker in \
	FAISAL_M99_BOOT_OK \
	M99_TOOL_SERVICE_OPEN_OK \
	M99_AUTHORITY_REFERENCE_OK \
	M99_TOOL_REGISTER_OK \
	M99_DUPLICATE_TOOL_REJECTED_OK \
	M99_MODEL_OUTPUT_NOT_AUTHORITY_OK \
	M99_INVOCATION_ADMITTED_OK \
	M99_TOOL_REVOCATION_OK \
	M99_REVOKED_EXECUTION_DENIED_OK \
	M99_HIGH_RISK_POLICY_DENIAL_OK \
	M99_RISK_COST_APPROVAL_ADMITTED_OK \
	M99_BROKER_EXECUTION_STARTED_OK \
	M99_VERIFIED_COMPLETION_COMMITTED_OK \
	M99_INVOCATION_QUERY_OK \
	M99_CONCURRENT_QUERY_LOCKING_OK \
	M99_UNVERIFIED_RESULT_DENIED_OK \
	M99_REGISTRY_REPLAY_OK \
	M99_CORRUPTION_FAIL_CLOSED_OK \
	M99_SELFTEST_EXIT=0 \
	FAISAL_M99_TEST_RC=0; do
	grep -q "$marker" "$LOG"
done
if grep -Eq 'KASAN:|KCSAN:|data-race|BUG:|Oops:|Kernel panic|Call Trace' "$LOG"; then
	printf 'M99_KERNEL_DIAGNOSTIC_FOUND\n'
	exit 1
fi
printf 'FAISAL_M99_TOOL_REGISTRY_QEMU_PASS\n'
