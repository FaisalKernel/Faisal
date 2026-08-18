#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_SELF_HEALING_ROOTFS:-$ROOT/build/qemu-faisal-self-healing-hardened}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_self_healing_test"
QEMU_SMP=${FAISAL_QEMU_SMP:-1}
QEMU_MEMORY=${FAISAL_QEMU_MEMORY:-768M}
QEMU_TIMEOUT_SECONDS=${FAISAL_QEMU_TIMEOUT_SECONDS:-180}
QEMU_ACPI=${FAISAL_QEMU_ACPI:-off}

case "$QEMU_ACPI" in
  on) QEMU_MACHINE='pc' ;;
  off) QEMU_MACHINE='pc,acpi=off' ;;
  *) echo 'FAISAL_QEMU_ACPI must be on or off' >&2; exit 2 ;;
esac

cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -I"$LINUX/include/uapi" \
  -I"$LINUX/tools/faisal-memory" \
  -I"$LINUX/tools/faisal-deploy" \
  -I"$LINUX/tools/faisal-self-healing" \
  -I"$LINUX/tools/faisal-attestation" \
  -I"$LINUX/tools/faisal-runtime-verification" \
  "$LINUX/tools/faisal-memory/faisal_memory_service.c" \
  "$LINUX/tools/faisal-deploy/faisal_deploy_supervisor.c" \
  "$LINUX/tools/faisal-self-healing/faisal_self_healing.c" \
  "$LINUX/tools/faisal-attestation/faisal_runtime_attestation.c" \
  "$LINUX/tools/faisal-runtime-verification/faisal_runtime_verification.c" \
  "$LINUX/tools/testing/selftests/agi_self_healing_test.c" \
  -o "$TEST" -lcrypto -ldl -lpthread

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$TEST" "$ROOTFS/bin/agi_self_healing_test"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/mount"
ln -s busybox "$ROOTFS/bin/cat"
ln -s busybox "$ROOTFS/bin/mknod"

cat > "$ROOTFS/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tmpfs -o mode=1777 none /tmp
if [ -r /sys/class/misc/agi_lifecycle/dev ]; then
  dev=$(cat /sys/class/misc/agi_lifecycle/dev)
  major=${dev%:*}
  minor=${dev#*:}
  mknod /dev/agi_lifecycle c "$major" "$minor" 2>/dev/null || true
fi
if [ ! -e /dev/agi_lifecycle ]; then
  echo FAISAL_SELF_HEALING_DEVICE_NODE_MISSING
  echo FAISAL_SELF_HEALING_RC=1
  poweroff -f
fi
echo FAISAL_SELF_HEALING_BOOT_OK
/bin/agi_self_healing_test
rc=$?
echo FAISAL_SELF_HEALING_RC=$rc
echo FAISAL_SELF_HEALING_COMPLETE
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )

set +e
timeout "${QEMU_TIMEOUT_SECONDS}s" qemu-system-x86_64 \
  -M "$QEMU_MACHINE" -accel tcg,thread=multi -cpu qemu64 \
  -smp "$QEMU_SMP" -m "$QEMU_MEMORY" \
  -kernel "$BUILD/arch/x86/boot/bzImage" \
  -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' -nographic -no-reboot > "$LOG" 2>&1 &
qemu_pid=$!
qemu_rc=124
deadline=$(( $(date +%s) + QEMU_TIMEOUT_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if grep -q 'FAISAL_SELF_HEALING_COMPLETE' "$LOG" 2>/dev/null; then
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
printf 'FAISAL_SELF_HEALING_QEMU_RC=%s\n' "$qemu_rc" >> "$LOG"
[ "$qemu_rc" -ne 124 ]
grep -q 'FAISAL_SELF_HEALING_BOOT_OK' "$LOG"
grep -q 'FAS_SELFTEST_EXIT=0' "$LOG"
grep -q 'FAISAL_SELF_HEALING_RC=0' "$LOG"
grep -q 'FAISAL_SELF_HEALING_COMPLETE' "$LOG"
if grep -Eq 'BUG:|Oops:|Kernel panic|WARNING:.*kernel|general protection fault|KASAN:|KCSAN:|UBSAN:|rcu:.*stall|rcu_preempt.*stall|RCU_GP_WAIT_FQS|kthread starved|possible circular locking dependency|data-race|use-after-free|kernel BUG' "$LOG"; then
  echo FAISAL_SELF_HEALING_KERNEL_DIAGNOSTIC_FOUND >&2
  exit 1
fi
echo FAISAL_SELF_HEALING_QEMU_VALIDATION_OK
