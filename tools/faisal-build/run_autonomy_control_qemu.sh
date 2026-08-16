#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
RUN_ID=${FAISAL_RUN_ID:-$(date +%s%N)}
ROOTFS=${FAISAL_ROOTFS:-$ROOT/build/qemu-faisal-autonomy-control-$RUN_ID}
LOG=${FAISAL_LOG:-$ROOTFS/qemu.log}
TEST=${FAISAL_TEST:-$ROOT/build/agi_autonomy_control_test}

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$TEST" "$ROOTFS/bin/agi_autonomy_control_test"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/mount"
ln -s busybox "$ROOTFS/bin/echo"
ln -s busybox "$ROOTFS/bin/cat"
ln -s busybox "$ROOTFS/bin/mknod"
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
  echo FAC_DEVICE_NODE_MISSING
  echo FAC_TEST_RC=1
  poweroff -f
fi
echo FAC_BOOT_OK
/bin/agi_autonomy_control_test
rc=$?
echo FAC_TEST_RC=$rc
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
qemu-system-x86_64 \
  -M pc -accel tcg,thread=multi -cpu qemu64 -smp 2 -m 768M \
  -kernel "$BUILD/arch/x86/boot/bzImage" \
  -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' -nographic -no-reboot > "$LOG" 2>&1 || true

grep -q 'FAC_BOOT_OK' "$LOG"
grep -q 'FAC_DEPLOY_BLOCKED_WITHOUT_APPROVALS_OK' "$LOG"
grep -q 'FAC_INDEPENDENT_APPROVAL_CANARY_DEPLOY_OK' "$LOG"
grep -q 'FAC_ROLLBACK_OK' "$LOG"
grep -q 'FAC_SELFTEST_EXIT=0' "$LOG"
if grep -Eq 'BUG:|Oops:|kernel panic|Kernel panic|WARNING:|KASAN:|KCSAN:|Call Trace:' "$LOG"; then
  echo 'FAC_KERNEL_DIAGNOSTIC_FAILURE' >&2
  exit 1
fi
printf '%s\n' 'M104_AUTONOMY_CONTROL_QEMU_VALIDATION_OK'
