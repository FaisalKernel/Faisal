#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD="${BUILD:-$ROOT/build/recovered}"
ROOTFS="${ROOTFS:-$ROOT/build/qemu-faisal-m81-concurrency}"
LOG="$ROOTFS/qemu.log"
TESTER="$ROOTFS/bin/agi_concurrent_lifecycle_ipc_test"
QEMU_SMP="${QEMU_SMP:-4}"
QEMU_MEM="${QEMU_MEM:-768M}"
QEMU_TIMEOUT_SECONDS="${QEMU_TIMEOUT_SECONDS:-180}"
QEMU_ACPI="${QEMU_ACPI:-off}"
case "$QEMU_ACPI" in
  on) QEMU_MACHINE='pc' ;;
  off) QEMU_MACHINE='pc,acpi=off' ;;
  *) echo 'QEMU_ACPI must be on or off' >&2; exit 2 ;;
esac

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -I"$LINUX/include/uapi" -I"$LINUX/tools/faisal-concurrency" \
  "$LINUX/tools/faisal-concurrency/faisal_concurrency_service.c" \
  "$LINUX/tools/testing/selftests/agi_concurrent_lifecycle_ipc_test.c" \
  -o "$TESTER" -lpthread
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/mount"
ln -s busybox "$ROOTFS/bin/echo"
ln -s busybox "$ROOTFS/bin/cat"
ln -s busybox "$ROOTFS/bin/mknod"
ln -s busybox "$ROOTFS/bin/poweroff"
cat > "$ROOTFS/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs -o mode=1777 none /tmp
if [ -r /sys/class/misc/agi_lifecycle/dev ]; then
  dev=$(cat /sys/class/misc/agi_lifecycle/dev)
  major=${dev%:*}
  minor=${dev#*:}
  mknod /dev/agi_lifecycle c "$major" "$minor" 2>/dev/null || true
fi
if [ ! -e /dev/agi_lifecycle ]; then
  echo FAISAL_M81_DEVICE_NODE_MISSING
  echo FAISAL_M81_TEST_RC=1
  poweroff -f
fi
echo FAISAL_M81_BOOT_OK
/bin/agi_concurrent_lifecycle_ipc_test
rc=$?
echo FAISAL_M81_TEST_RC=$rc
echo FAISAL_M81_TEST_COMPLETE
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout "${QEMU_TIMEOUT_SECONDS}s" qemu-system-x86_64 \
  -M "$QEMU_MACHINE" \
  -accel tcg,thread=multi \
  -cpu qemu64 \
  -smp "$QEMU_SMP" \
  -m "$QEMU_MEM" \
  -kernel "$BUILD/arch/x86/boot/bzImage" \
  -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' \
  -nographic -no-reboot > "$LOG" 2>&1 &
qemu_pid=$!
qemu_rc=124
deadline=$(( $(date +%s) + QEMU_TIMEOUT_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if grep -q 'FAISAL_M81_TEST_COMPLETE' "$LOG" 2>/dev/null; then
    kill -TERM "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_rc=0
    break
  fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    wait "$qemu_pid" 2>/dev/null
    qemu_rc=$?
    break
  fi
  sleep 1
done
if kill -0 "$qemu_pid" 2>/dev/null; then
  kill -TERM "$qemu_pid" 2>/dev/null || true
  wait "$qemu_pid" 2>/dev/null || true
fi
set -e
printf 'FAISAL_M81_QEMU_RC=%s\n' "$qemu_rc" >> "$LOG"
[ "$qemu_rc" -ne 124 ]

grep -q 'FAISAL_M81_BOOT_OK' "$LOG"
grep -q 'M81_WORKERS_OK workers=8 passes=8' "$LOG"
grep -q 'M81_MALFORMED_UAPI_REJECT_OK cases=512' "$LOG"
grep -q 'M81_CAPABILITY_ISOLATION_OK denials=16' "$LOG"
grep -q 'M81_CANCELLATION_OK passes=48' "$LOG"
grep -q 'M81_IPC_ROUNDTRIP_OK sent=768 received=768' "$LOG"
grep -q 'M81_QUEUE_PRESSURE_OK events=' "$LOG"
grep -q 'M81_RANDOMIZED_INPUTS_OK cases=872' "$LOG"
grep -q 'M81_SELFTEST_EXIT=0' "$LOG"
grep -q 'FAISAL_M81_TEST_RC=0' "$LOG"
grep -q 'FAISAL_M81_TEST_COMPLETE' "$LOG"
if grep -Eq 'BUG:|Oops:|Kernel panic|WARNING:.*kernel|general protection fault|KASAN:|KCSAN:|UBSAN:|rcu:.*stall|rcu_preempt.*stall|RCU_GP_WAIT_FQS|kthread starved|possible circular locking dependency|data-race|use-after-free|kernel BUG' "$LOG"; then
  echo FAISAL_M81_KERNEL_DIAGNOSTIC_FOUND >&2
  exit 1
fi
printf '%s\n' 'M81_QEMU_VALIDATION_OK'
