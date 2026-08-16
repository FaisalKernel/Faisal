#!/bin/sh
set -eu

OUT=${BUILD:-/home/ubuntu/agi-kernel/build/superiority-agi}
ROOT=${ROOTFS:-/home/ubuntu/agi-kernel/build/qemu-faisal-m101-scheduler/rootfs}
IMAGE=${IMAGE:-/home/ubuntu/agi-kernel/build/qemu-faisal-m101-scheduler/initramfs.cpio.gz}
LOG=${LOG:-/home/ubuntu/agi-kernel/build/qemu-faisal-m101-scheduler/qemu.log}
SELFTEST=${SELFTEST:-/home/ubuntu/agi-kernel/build/superiority-agi/agi_scheduler_urgency_test.static}

[ -r "$OUT/arch/x86/boot/bzImage" ]
[ -x "$SELFTEST" ]
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/tmp"
cp "$(command -v busybox)" "$ROOT/bin/busybox"
cp "$SELFTEST" "$ROOT/bin/agi_scheduler_urgency_test"
ln -sf busybox "$ROOT/bin/sh"
ln -sf busybox "$ROOT/bin/mknod"

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
  printf 'FAISAL_M101_DEVICE_NODE_MISSING\n'
  printf 'FAISAL_M101_TEST_RC=1\n'
  poweroff -f
fi
printf 'FAISAL_M101_BOOT_OK\n'
/bin/agi_scheduler_urgency_test
rc=$?
printf 'FAISAL_M101_TEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOT/init"
mkdir -p "$(dirname "$IMAGE")" "$(dirname "$LOG")"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$IMAGE")

set +e
timeout 120s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 \
  -m 512M -smp "${QEMU_SMP:-1}" -kernel "$OUT/arch/x86/boot/bzImage" \
  -initrd "$IMAGE" -append 'console=ttyS0 rdinit=/init quiet' \
  -nographic -no-reboot -monitor none -serial "file:$LOG" \
  >/tmp/faisal-m101-scheduler-qemu-stderr.log 2>&1
rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m101-scheduler-qemu-stderr.log 2>/dev/null || true
printf 'QEMU_RC=%s\n' "$rc"
[ "$rc" -eq 0 ]
markers="FAISAL_M101_BOOT_OK M101_SCHED_HINT_READBACK_OK M101_SCHED_SELFTEST_EXIT=0 FAISAL_M101_TEST_RC=0"
if [ "${EXPECT_URGENCY:-1}" = 1 ]; then
  markers="$markers M101_SCHED_DEADLINE_URGENCY_OK"
else
  markers="$markers M101_SCHED_BASELINE_NO_URGENCY_OK"
fi
for marker in $markers; do
  if ! grep -q "$marker" "$LOG"; then
    printf 'M101_MISSING_MARKER=%s\n' "$marker"
    exit 1
  fi
done
if grep -Eq 'KASAN:|KCSAN:|data-race|BUG:|Oops:|Kernel panic|Call Trace' "$LOG"; then
  printf 'M101_KERNEL_DIAGNOSTIC_FOUND\n'
  exit 1
fi
printf 'FAISAL_M101_SCHEDULER_URGENCY_QEMU_PASS\n'
