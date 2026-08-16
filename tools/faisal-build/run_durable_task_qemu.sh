#!/bin/sh
set -eu
OUT=${BUILD:-/home/ubuntu/agi-kernel/build/recovered}
ROOT=${ROOTFS:-/home/ubuntu/agi-kernel/build/qemu-faisal-m95-durable-task/rootfs}
IMAGE=${IMAGE:-/home/ubuntu/agi-kernel/build/qemu-faisal-m95-durable-task/initramfs.cpio.gz}
LOG=${LOG:-/home/ubuntu/agi-kernel/build/qemu-faisal-m95-durable-task/qemu.log}
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/tmp"
cp "$(command -v busybox)" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
ln -sf busybox "$ROOT/bin/mknod"
cp "$OUT/agi_durable_task_test" "$ROOT/bin/agi_durable_task_test"
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
  printf 'FAISAL_M95_DEVICE_NODE_MISSING\n'
  printf 'FAISAL_M95_TEST_RC=1\n'
  poweroff -f
fi
printf 'FAISAL_M95_BOOT_OK\n'
/bin/agi_durable_task_test --require-kernel
rc=$?
printf 'FAISAL_M95_TEST_RC=%s\n' "$rc"
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
	>/tmp/faisal-m95-durable-task-qemu-stderr.log 2>&1
rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m95-durable-task-qemu-stderr.log 2>/dev/null || true
printf 'QEMU_RC=%s\n' "$rc"
grep -q 'FAISAL_M95_BOOT_OK' "$LOG"
grep -q 'M95_KERNEL_SESSION_BIND_OK abi=38' "$LOG"
grep -q 'M95_DURABLE_TASK_SERVICE_OPEN_OK' "$LOG"
grep -q 'M95_IDEMPOTENT_SUBMIT_OK' "$LOG"
grep -q 'M95_DEPENDENCY_GATE_OK' "$LOG"
grep -q 'M95_LEASE_HEARTBEAT_COMPLETE_OK' "$LOG"
grep -q 'M95_RETRY_BACKOFF_REPLAN_OK' "$LOG"
grep -q 'M95_RESTART_RECOVERY_OK' "$LOG"
grep -q 'M95_POLICY_CANCEL_STOP_OK' "$LOG"
grep -q 'M95_DEADLINE_STOP_OK' "$LOG"
grep -q 'M95_BUDGET_STOP_OK' "$LOG"
grep -q 'M95_CONCURRENT_QUERY_OK' "$LOG"
grep -q 'M95_REPLAY_STATE_OK' "$LOG"
grep -q 'M95_CORRUPTION_FAIL_CLOSED_OK' "$LOG"
grep -q 'M95_SELFTEST_EXIT=0' "$LOG"
grep -q 'FAISAL_M95_TEST_RC=0' "$LOG"
if grep -Eq 'KASAN:|KCSAN:|data-race|BUG:|Oops:|Kernel panic|Call Trace' "$LOG"; then
  printf 'M95_KERNEL_DIAGNOSTIC_FOUND\n'
  exit 1
fi
printf 'FAISAL_M95_DURABLE_TASK_QEMU_PASS\n'
