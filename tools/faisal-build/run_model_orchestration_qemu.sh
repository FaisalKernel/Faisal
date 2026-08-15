#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
BUILD="$ROOT/build/recovered"
ROOTFS="$ROOT/build/qemu-faisal-model-orchestration"
LOG="$ROOTFS/qemu.log"

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$BUILD/agi_model_orchestration_test" "$ROOTFS/bin/agi_model_orchestration_test"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/mount"
ln -s busybox "$ROOTFS/bin/echo"
cat > "$ROOTFS/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
if [ -r /sys/class/misc/agi_lifecycle/dev ]; then
  dev=$(cat /sys/class/misc/agi_lifecycle/dev)
  major=${dev%:*}
  minor=${dev#*:}
  mknod /dev/agi_lifecycle c "$major" "$minor" 2>/dev/null || true
fi
if [ ! -e /dev/agi_lifecycle ]; then
  echo FAISAL_M74_DEVICE_NODE_MISSING
  echo FAISAL_M74_TEST_RC=1
  poweroff -f
fi
echo FAISAL_M74_BOOT_OK
/bin/agi_model_orchestration_test
rc=$?
echo FAISAL_M74_TEST_RC=$rc
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
qemu-system-x86_64 \
  -M pc \
  -accel tcg,thread=multi \
  -cpu qemu64 \
  -smp 2 \
  -m 512M \
  -kernel "$BUILD/arch/x86/boot/bzImage" \
  -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' \
  -nographic \
  -no-reboot \
  > "$LOG" 2>&1 || true

grep -q 'FAISAL_M74_BOOT_OK' "$LOG"
grep -q 'M74_SELFTEST_EXIT=0' "$LOG"
grep -q 'FAISAL_M74_TEST_RC=0' "$LOG"
printf '%s\n' 'M74_QEMU_VALIDATION_OK'
