#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/m115-focused}
ROOTFS=${FAISAL_TENANT_ROOTFS:-$ROOT/build/qemu-faisal-m115-tenant}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_tenant_accounting_test"
BATCHER_TEST="$BUILD/faisal_accelerator_batcher_test"

cc -O2 -Wall -Wextra -Werror -Wno-cpp -Wno-deprecated-declarations -static \
  -I"$LINUX/include/uapi" -I"$LINUX/include" \
  "$LINUX/tools/testing/selftests/agi_tenant_accounting_test.c" -o "$TEST"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -Wno-deprecated-declarations -static \
  -I"$LINUX/include/uapi" -I"$LINUX/include" \
  -I"$LINUX/tools/faisal-accelerator" \
  "$LINUX/tools/faisal-accelerator/faisal_accelerator_batcher.c" \
  "$LINUX/tools/testing/selftests/faisal_accelerator_batcher_test.c" -o "$BATCHER_TEST"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -sf busybox "$ROOTFS/bin/sh"
cp "$TEST" "$ROOTFS/bin/agi_tenant_accounting_test"
cp "$BATCHER_TEST" "$ROOTFS/bin/faisal_accelerator_batcher_test"
cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /sys/fs/cgroup
mount -t cgroup2 none /sys/fs/cgroup || { echo M151_CGROUP2_MOUNT_FAIL; exit 1; }
grep -qw cpu /sys/fs/cgroup/cgroup.controllers || { echo M152_CPU_CONTROLLER_UNAVAILABLE; exit 1; }
printf '+cpu\n' > /sys/fs/cgroup/cgroup.subtree_control || { echo M152_CPU_CONTROLLER_ENABLE_FAIL; exit 1; }
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
printf 'FAISAL_M115_BOOT_OK\n'
[ -e /dev/agi_lifecycle ] || { echo M115_DEVICE_NODE_MISSING; exit 1; }
/bin/agi_tenant_accounting_test
rc=$?
printf 'M115_SELFTEST_RC=%s\n' "$rc"
[ "$rc" -eq 0 ] || { poweroff -f; exit 1; }
/bin/faisal_accelerator_batcher_test
rc=$?
printf 'M163_BATCHER_SELFTEST_RC=%s\n' "$rc"
[ "$rc" -eq 0 ] || { poweroff -f; exit 1; }
poweroff -f
INIT
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -m 512M -smp 1 \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot -monitor none \
  -serial "file:$LOG" >/tmp/faisal-m115-tenant-qemu-stderr.log 2>&1
qemu_rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m115-tenant-qemu-stderr.log 2>/dev/null || true
printf 'M115_QEMU_RC=%s\n' "$qemu_rc"
[ "$qemu_rc" -ne 124 ]
for marker in FAISAL_M115_BOOT_OK M151_TENANT_CGROUP_OWNER_OK M151_TENANT_CGROUP_QUERY_OK M153_TENANT_CGROUP_TASK_MOVE_OK M152_TENANT_CPU_THROTTLE_SET_OK M153_TENANT_CPU_THROTTLE_OBSERVED_OK M152_TENANT_CPU_STALE_GENERATION_DENY_OK M152_TENANT_CPU_THROTTLE_QUERY_OK M152_TENANT_CPU_THROTTLE_CLEAR_OK M153_TENANT_ACCELERATOR_RELEASE_UNDERFLOW_DENY_OK M153_TENANT_ACCELERATOR_MEMORY_RELEASE_OK M154_TENANT_ACCELERATOR_TELEMETRY_LOSS_OK M156_TENANT_EVENT_BACKPRESSURE_QUERY_OK M160_ADAPTIVE_PRESSURE_CACHE_OK M161_COALESCED_SUBMIT_OK M162_ZERO_COPY_COALESCED_OK M163_DIRECT_PARTIAL_OK M164_SUBMIT_MANY_PRESSURE_CACHE_OK M163_BATCHER_SELFTEST_RC=0 M155_TENANT_ACCELERATOR_BATCH_ACCOUNTING_OK M155_TENANT_ACCELERATOR_BATCH_MALFORMED_REJECT_OK M155_TENANT_ACCELERATOR_BATCH_BENCH_OK M115_TENANT_BUDGET_SET_OK M115_TENANT_BUDGET_ADMISSION_DENY_OK M115_TENANT_BUDGET_QUERY_OK M115_TENANT_AGGREGATE_OK M115_TENANT_MALFORMED_REJECT_OK M115_TENANT_BUDGET_CLEAR_OK M153_TENANT_PARENT_TASK_RESTORE_OK M151_TENANT_CGROUP_RELEASE_OK M115_SELFTEST_EXIT=0 M115_SELFTEST_RC=0; do
  grep -q "$marker" "$LOG"
done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then
  exit 1
fi
echo M115_TENANT_ACCOUNTING_QEMU_VALIDATION_OK
