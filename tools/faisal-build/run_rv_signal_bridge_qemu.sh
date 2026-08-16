#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD="${BUILD:-$ROOT/build/m88-rv}"
ROOTFS="${ROOTFS:-$ROOT/build/qemu-faisal-m88-rv-bridge}"
LOG="$ROOTFS/qemu.log"
TESTER="$BUILD/agi_rv_signal_bridge_test"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp" "$ROOTFS/sys/kernel/tracing"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -I"$LINUX/include/uapi" \
  "$LINUX/tools/testing/selftests/agi_rv_signal_bridge_test.c" \
  -o "$TESTER"
make -C "$BUILD" M="$LINUX/tools/faisal-rv" modules > "$ROOTFS/module-build.log" 2>&1
cp "$TESTER" "$ROOTFS/bin/agi_rv_signal_bridge_test"
cp "$LINUX/tools/faisal-rv/faisal_rv_bridge_fixture.ko" "$ROOTFS/bin/faisal_rv_bridge_fixture.ko"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/mount"
ln -s busybox "$ROOTFS/bin/cat"
ln -s busybox "$ROOTFS/bin/echo"
ln -s busybox "$ROOTFS/bin/mknod"
ln -s busybox "$ROOTFS/bin/insmod"
cat > "$ROOTFS/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t tmpfs -o mode=1777 none /tmp
if [ -r /sys/class/misc/agi_lifecycle/dev ]; then
  dev=$(cat /sys/class/misc/agi_lifecycle/dev)
  major=${dev%:*}
  minor=${dev#*:}
  mknod /dev/agi_lifecycle c "$major" "$minor" 2>/dev/null || true
fi
if [ ! -e /dev/agi_lifecycle ]; then
  echo FAISAL_M88_DEVICE_NODE_MISSING
  echo FAISAL_M88_TEST_RC=1
  poweroff -f
fi
if [ ! -e /sys/kernel/tracing/rv/enabled_monitors ]; then
  echo FAISAL_M88_RV_INTERFACE_MISSING
  echo FAISAL_M88_TEST_RC=1
  poweroff -f
fi
echo 1000 > /sys/module/stall/parameters/threshold_jiffies 2>/dev/null || true
echo 1 > /sys/kernel/tracing/tracing_on
echo stall > /sys/kernel/tracing/rv/enabled_monitors
echo 1 > /sys/kernel/tracing/rv/monitoring_on
echo 1 > /sys/kernel/tracing/rv/reacting_on
printf 'M88_RV_AVAILABLE='; cat /sys/kernel/tracing/rv/available_monitors 2>/dev/null || true
printf 'M88_RV_ENABLED='; cat /sys/kernel/tracing/rv/enabled_monitors 2>/dev/null || true
printf 'M88_RV_MONITORING='; cat /sys/kernel/tracing/rv/monitoring_on 2>/dev/null || true
printf 'M88_RV_REACTING='; cat /sys/kernel/tracing/rv/reacting_on 2>/dev/null || true
printf 'M88_RV_THRESHOLD='; cat /sys/module/stall/parameters/threshold_jiffies 2>/dev/null || true
# The test-only module below invokes the same upstream rv_react path used
# by monitor violations. No scheduler flood is needed for this bridge test;
# avoiding it keeps the QEMU signal-provenance result free of unrelated RCU
# starvation noise. Wait for the selftest to configure both sessions before
# loading the fixture, rather than relying on a timing-sensitive sleep.
echo FAISAL_M88_BOOT_OK
(
  i=0
  while [ ! -e /tmp/m88-subscribed ] && [ "$i" -lt 8 ]; do
    sleep 1
    i=$((i + 1))
  done
  if [ ! -e /tmp/m88-subscribed ]; then
    echo FAISAL_M88_READINESS_TIMEOUT
    exit 1
  fi
  insmod /bin/faisal_rv_bridge_fixture.ko
) &
/bin/agi_rv_signal_bridge_test
rc=$?
echo FAISAL_M88_TEST_RC=$rc
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
MEM="${QEMU_MEM:-1024M}"
SMP="${QEMU_SMP:-2}"
qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -smp "$SMP" -m "$MEM" \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' -nographic -no-reboot > "$LOG" 2>&1 || true
grep -q 'FAISAL_M88_BOOT_OK' "$LOG"
grep -q 'M88_SUBSCRIPTION_SETUP_OK' "$LOG"
grep -q 'M88_RV_PROVENANCE_OK' "$LOG"
grep -q 'M88_CAPABILITY_FILTER_OK' "$LOG"
grep -q 'M88_SELFTEST_EXIT=0' "$LOG"
grep -q 'FAISAL_M88_TEST_RC=0' "$LOG"
printf '%s\n' 'M88_RV_SIGNAL_BRIDGE_QEMU_VALIDATION_OK'
