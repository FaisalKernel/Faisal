#!/bin/sh
set -eu
OUT=${BUILD:-/home/ubuntu/agi-kernel/build/recovered}
ROOT=${ROOTFS:-/home/ubuntu/agi-kernel/build/qemu-faisal-m94-intent-lease/rootfs}
IMAGE=${IMAGE:-/home/ubuntu/agi-kernel/build/qemu-faisal-m94-intent-lease/initramfs.cpio.gz}
LOG=${LOG:-/home/ubuntu/agi-kernel/build/qemu-faisal-m94-intent-lease/qemu.log}
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/tmp"
cp "$(command -v busybox)" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
ln -sf busybox "$ROOT/bin/mknod"
cp "$OUT/agi_intent_lease_test" "$ROOT/bin/agi_intent_lease_test"
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
  printf 'FAISAL_M94_DEVICE_NODE_MISSING\n'
  printf 'FAISAL_M94_TEST_RC=1\n'
  poweroff -f
fi
printf 'FAISAL_M94_BOOT_OK\n'
/bin/agi_intent_lease_test
rc=$?
printf 'FAISAL_M94_TEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOT/init"
mkdir -p "$(dirname "$IMAGE")" "$(dirname "$LOG")"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$IMAGE")
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 \
	-m 512M -smp "${QEMU_SMP:-2}" -kernel "$OUT/arch/x86/boot/bzImage" \
	-initrd "$IMAGE" -append 'console=ttyS0 rdinit=/init quiet' \
	-nographic -no-reboot \
	-monitor none -serial "file:$LOG" >/tmp/faisal-m94-intent-lease-qemu-stderr.log 2>&1
rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m94-intent-lease-qemu-stderr.log 2>/dev/null || true
printf 'QEMU_RC=%s\n' "$rc"
grep -q 'FAISAL_M94_BOOT_OK' "$LOG"
grep -q 'M94_INTENT_LEASE_ACQUIRE_OK' "$LOG"
grep -q 'M94_SINGLE_USE_ATOMIC_CONSUME_OK' "$LOG"
grep -q 'M94_REPLAY_DENIAL_OK' "$LOG"
grep -q 'M94_BOUNDED_MULTI_USE_OK' "$LOG"
grep -q 'M94_INTENT_QUERY_OK' "$LOG"
grep -q 'M94_INTENT_MISMATCH_DENIAL_OK' "$LOG"
grep -q 'M94_EXPIRY_FAIL_CLOSED_OK' "$LOG"
grep -q 'M94_GRANT_GATING_DENIAL_OK' "$LOG"
grep -q 'M94_REVOCATION_FAIL_CLOSED_OK' "$LOG"
grep -q 'M94_SESSION_CLOSE_INVALIDATION_OK' "$LOG"
grep -q 'M94_SELFTEST_EXIT=0' "$LOG"
printf 'FAISAL_M94_INTENT_LEASE_QEMU_PASS\n'
