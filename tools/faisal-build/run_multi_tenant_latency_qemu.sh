#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/m156-backpressure}
ROOTFS=${FAISAL_MT_ROOTFS:-$ROOT/build/qemu-faisal-mt-latency}
LOG=${FAISAL_MT_LOG:-$ROOT/build/faisal-mt-latency-qemu.log}
ITERATIONS=${FAISAL_MT_ITERATIONS:-256}
BENCH="$BUILD/faisal_accelerator_multi_tenant_benchmark"

cc -O2 -Wall -Wextra -Werror -Wno-cpp -Wno-deprecated-declarations -static \
  -I"$LINUX/include/uapi" -I"$LINUX/include" \
  "$LINUX/tools/testing/selftests/faisal_accelerator_multi_tenant_benchmark.c" -o "$BENCH"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -sf busybox "$ROOTFS/bin/sh"
cp "$BENCH" "$ROOTFS/bin/faisal_accelerator_multi_tenant_benchmark"
cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /sys/fs/cgroup
mount -t cgroup2 none /sys/fs/cgroup || { echo FAISAL_MT_CGROUP2_MOUNT_FAIL; exit 1; }
grep -qw cpu /sys/fs/cgroup/cgroup.controllers || { echo FAISAL_MT_CPU_CONTROLLER_UNAVAILABLE; exit 1; }
printf '+cpu\n' > /sys/fs/cgroup/cgroup.subtree_control || { echo FAISAL_MT_CPU_CONTROLLER_ENABLE_FAIL; exit 1; }
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
printf 'FAISAL_MT_QEMU_BOOT_OK\n'
[ -e /dev/agi_lifecycle ] || { echo FAISAL_MT_DEVICE_NODE_MISSING; exit 1; }
for tenants in 1 2 4 8; do
  /bin/faisal_accelerator_multi_tenant_benchmark "$tenants" "__ITERATIONS__"
  rc=$?
  printf 'FAISAL_MT_LEVEL_RC tenants=%s rc=%s\n' "$tenants" "$rc"
  [ "$rc" -eq 0 ] || { poweroff -f; exit 1; }
done
printf 'FAISAL_MT_BENCHMARK_RC=0\n'
poweroff -f
INIT
chmod +x "$ROOTFS/init"
# Bake the iteration count into init without using shell interpolation in the heredoc.
sed -i "s/__ITERATIONS__/$ITERATIONS/g" "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout 180s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -m 768M -smp 2 \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot -monitor none \
  -serial "file:$LOG" >/tmp/faisal-multi-tenant-latency-qemu-stderr.log 2>&1
qemu_rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-multi-tenant-latency-qemu-stderr.log 2>/dev/null || true
printf 'FAISAL_MT_QEMU_RC=%s\n' "$qemu_rc"
[ "$qemu_rc" -ne 124 ]
grep -q 'FAISAL_MT_QEMU_BOOT_OK' "$LOG"
grep -q 'FAISAL_MT_LEVEL_OK tenants=1 ' "$LOG"
grep -q 'FAISAL_MT_LEVEL_OK tenants=2 ' "$LOG"
grep -q 'FAISAL_MT_LEVEL_OK tenants=4 ' "$LOG"
grep -q 'FAISAL_MT_LEVEL_OK tenants=8 ' "$LOG"
grep -q 'FAISAL_MT_LEVEL_RC tenants=1 rc=0' "$LOG"
grep -q 'FAISAL_MT_LEVEL_RC tenants=2 rc=0' "$LOG"
grep -q 'FAISAL_MT_LEVEL_RC tenants=4 rc=0' "$LOG"
grep -q 'FAISAL_MT_LEVEL_RC tenants=8 rc=0' "$LOG"
grep -q 'FAISAL_MT_BENCHMARK_RC=0' "$LOG"
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then
  exit 1
fi
echo FAISAL_MT_QEMU_LATENCY_VALIDATION_OK
