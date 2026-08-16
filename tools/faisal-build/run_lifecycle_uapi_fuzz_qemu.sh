#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_FUZZ_ROOTFS:-$ROOT/build/qemu-faisal-uapi-fuzz}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_lifecycle_uapi_fuzz_test"
FUZZ_ITERATIONS=${FAISAL_UAPI_FUZZ_ITERATIONS:-4096}

cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -I"$LINUX/include/uapi" \
  "$LINUX/tools/testing/selftests/agi_lifecycle_uapi_fuzz_test.c" \
  -o "$TEST"

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$TEST" "$ROOTFS/bin/agi_lifecycle_uapi_fuzz_test"
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
  echo FAISAL_UAPI_FUZZ_DEVICE_NODE_MISSING
  echo FAISAL_UAPI_FUZZ_RC=1
  poweroff -f
fi
echo FAISAL_UAPI_FUZZ_BOOT_OK
  /bin/agi_lifecycle_uapi_fuzz_test /dev/agi_lifecycle __FAISAL_UAPI_FUZZ_ITERATIONS__

rc=$?
echo FAISAL_UAPI_FUZZ_RC=$rc
poweroff -f
EOF
sed -i "s/__FAISAL_UAPI_FUZZ_ITERATIONS__/$FUZZ_ITERATIONS/" "$ROOTFS/init"
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
qemu-system-x86_64 \
  -M pc \
  -accel tcg,thread=multi \
  -cpu qemu64 \
  -smp 2 \
  -m 768M \
  -kernel "$BUILD/arch/x86/boot/bzImage" \
  -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' \
  -nographic \
  -no-reboot \
  > "$LOG" 2>&1 || true

grep -q 'FAISAL_UAPI_FUZZ_BOOT_OK' "$LOG"
grep -q 'FAISAL_UAPI_FUZZ_OK' "$LOG"
grep -q 'FAISAL_UAPI_FUZZ_RC=0' "$LOG"
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel' "$LOG"; then
  echo 'FAISAL_UAPI_FUZZ_KERNEL_DIAGNOSTIC_FOUND' >&2
  exit 1
fi
printf '%s\n' 'FAISAL_UAPI_FUZZ_QEMU_VALIDATION_OK'
