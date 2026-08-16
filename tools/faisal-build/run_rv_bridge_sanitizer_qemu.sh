#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD="${BUILD:-$ROOT/build/m89-rv-sanitizer}"
ROOTFS="${ROOTFS:-$ROOT/build/qemu-faisal-m89-rv-sanitizer}"
LOG="$ROOTFS/qemu.log"
TESTER="$BUILD/agi_rv_bridge_concurrency_test"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp" "$ROOTFS/sys/kernel/tracing"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -I"$LINUX/include/uapi" \
  "$LINUX/tools/testing/selftests/agi_rv_bridge_concurrency_test.c" \
  -o "$TESTER"
make -C "$BUILD" M="$LINUX/tools/faisal-rv" modules > "$ROOTFS/module-build.log" 2>&1
cp "$TESTER" "$ROOTFS/bin/agi_rv_bridge_concurrency_test"
cp "$LINUX/tools/faisal-rv/faisal_rv_bridge_stress_fixture.ko" "$ROOTFS/bin/faisal_rv_bridge_stress_fixture.ko"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/mount"
ln -s busybox "$ROOTFS/bin/cat"
ln -s busybox "$ROOTFS/bin/echo"
ln -s busybox "$ROOTFS/bin/mknod"
ln -s busybox "$ROOTFS/bin/insmod"
ln -s busybox "$ROOTFS/bin/poweroff"
cat > "$ROOTFS/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t tmpfs -o mode=1777 none /tmp
if [ -r /sys/class/misc/agi_lifecycle/dev ]; then
  dev=$(cat /sys/class/misc/agi_lifecycle/dev)
  major=${dev%:*}
  minor=${dev#*:}
  mknod /dev/agi_lifecycle c "$major" "$minor" 2>/dev/null || true
fi
if [ ! -e /dev/agi_lifecycle ]; then
  echo M89_DEVICE_NODE_MISSING
  echo M89_TEST_RC=1
  poweroff -f
fi
if [ ! -e /sys/kernel/tracing/rv/enabled_monitors ]; then
  echo M89_RV_INTERFACE_MISSING
  echo M89_TEST_RC=1
  poweroff -f
fi
printf 'M89_RV_AVAILABLE='; cat /sys/kernel/tracing/rv/available_monitors 2>/dev/null || true
echo M89_BOOT_OK
(
  i=0
  while [ ! -e /tmp/m89-subscribed ] && [ "$i" -lt 120 ]; do
    sleep 1
    i=$((i + 1))
  done
  if [ ! -e /tmp/m89-subscribed ]; then
    echo M89_READINESS_TIMEOUT
    exit 1
  fi
  echo M89_BEFORE_INSMOD
  insmod /bin/faisal_rv_bridge_stress_fixture.ko
  echo M89_AFTER_INSMOD
) &
/bin/agi_rv_bridge_concurrency_test
rc=$?
echo M89_TEST_RC=$rc
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
MEM="${QEMU_MEM:-1024M}"
SMP="${QEMU_SMP:-1}"
qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -smp "$SMP" -m "$MEM" \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' -nographic -no-reboot > "$LOG" 2>&1 || true
grep -q 'M89_BOOT_OK' "$LOG"
grep -q 'M89_CONCURRENT_SETUP_OK' "$LOG"
grep -q 'M89_MALFORMED_CONSUMER_OK' "$LOG"
grep -q 'M89_CONCURRENT_PROVENANCE_OK' "$LOG"
grep -q 'M89_CAPABILITY_FILTER_OK' "$LOG"
grep -q 'M89_SELFTEST_EXIT=0' "$LOG"
grep -q 'M89_TEST_RC=0' "$LOG"
if grep -Eq 'KASAN:|KCSAN:|BUG: KASAN|data-race|WARNING: .*lockdep|possible circular locking dependency|general protection fault|use-after-free|kernel BUG|rcu: INFO|rcu: .*stall' "$LOG"; then
  echo M89_SANITIZER_FAILURE_MARKER
  exit 1
fi
printf '%s\n' 'M89_RV_BRIDGE_SANITIZER_QEMU_VALIDATION_OK'
