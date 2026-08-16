#!/bin/sh
set -eu

OUT=${BUILD:-/home/ubuntu/agi-kernel/build/superiority-agi}
ROOT=${ROOTFS:-/home/ubuntu/agi-kernel/build/qemu-faisal-m101-graph/rootfs}
IMAGE=${IMAGE:-/home/ubuntu/agi-kernel/build/qemu-faisal-m101-graph/initramfs.cpio.gz}
LOG=${LOG:-/home/ubuntu/agi-kernel/build/qemu-faisal-m101-graph/qemu.log}
SELFTEST=${SELFTEST:-/home/ubuntu/agi-kernel/build/recovered/agi_graph_telemetry_test}

[ -r "$OUT/arch/x86/boot/bzImage" ]
[ -x "$SELFTEST" ]
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/tmp"
cp "$(command -v busybox)" "$ROOT/bin/busybox"
cp "$SELFTEST" "$ROOT/bin/agi_graph_telemetry_test"
ln -sf busybox "$ROOT/bin/sh"
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
printf 'FAISAL_M101_GRAPH_BOOT_OK\n'
/bin/agi_graph_telemetry_test
rc=$?
printf 'FAISAL_M101_GRAPH_TEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOT/init"
mkdir -p "$(dirname "$IMAGE")" "$(dirname "$LOG")"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$IMAGE")
set +e
timeout 120s qemu-system-x86_64 -M pc -m 512M -smp 2 \
  -kernel "$OUT/arch/x86/boot/bzImage" -initrd "$IMAGE" \
  -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot \
  -monitor none -serial "file:$LOG" >/tmp/faisal-m101-graph-qemu-stderr.log 2>&1
rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m101-graph-qemu-stderr.log 2>/dev/null || true
printf 'QEMU_RC=%s\n' "$rc"
[ "$rc" -eq 0 ]
grep -q 'M69_SELFTEST_EXIT=0' "$LOG"
grep -q 'FAISAL_M101_GRAPH_TEST_RC=0' "$LOG"
if grep -Eq 'KASAN:|KCSAN:|data-race|BUG:|Oops:|Kernel panic|Call Trace' "$LOG"; then
  printf 'M101_GRAPH_KERNEL_DIAGNOSTIC_FOUND\n'
  exit 1
fi
printf 'FAISAL_M101_GRAPH_REGRESSION_PASS\n'
