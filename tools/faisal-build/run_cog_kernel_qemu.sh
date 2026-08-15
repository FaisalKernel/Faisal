#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD="$ROOT/build/recovered"
ROOTFS="$ROOT/build/qemu-cog-kernel"
LOG="$ROOTFS/qemu.log"
MODULE="$LINUX/tools/cog-kernel/cog_kernel.ko"
TESTER="$LINUX/tools/cog-kernel/cog_tester"

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp" "$ROOTFS/lib/modules"
cp "$BUILD/arch/x86/boot/bzImage" "$ROOTFS/boot.bzImage" 2>/dev/null || true
cp "$MODULE" "$ROOTFS/cog_kernel.ko"
cp "$TESTER" "$ROOTFS/bin/cog_tester"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/mount"
ln -s busybox "$ROOTFS/bin/insmod"
ln -s busybox "$ROOTFS/bin/rmmod"
ln -s busybox "$ROOTFS/bin/sleep"
ln -s busybox "$ROOTFS/bin/cat"
ln -s busybox "$ROOTFS/bin/echo"
cat > "$ROOTFS/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tmpfs -o mode=1777 none /tmp
insmod /cog_kernel.ko attention_drift=${COG_ATTENTION_DRIFT:-0}
sleep 1
if [ ! -e /dev/cog_kernel ]; then
  echo COG_DEVICE_NODE_MISSING
  echo COG_QEMU_TEST_RC=1
  rmmod cog_kernel 2>/dev/null || true
  poweroff -f
fi
echo COG_BOOT_OK
/bin/cog_tester
rc=$?
if [ "$rc" -eq 0 ]; then
  rmmod cog_kernel
  echo COG_MODULE_UNLOAD_OK
fi
echo COG_QEMU_TEST_RC=$rc
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

grep -q 'COG_BOOT_OK' "$LOG"
grep -q 'COG_TEST_EXIT=0' "$LOG"
grep -q 'COG_MODULE_UNLOAD_OK' "$LOG"
grep -q 'COG_QEMU_TEST_RC=0' "$LOG"
printf '%s\n' 'COG_KERNEL_QEMU_VALIDATION_OK'
