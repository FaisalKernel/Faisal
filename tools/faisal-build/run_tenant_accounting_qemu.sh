#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/m115-focused}
ROOTFS=${FAISAL_TENANT_ROOTFS:-$ROOT/build/qemu-faisal-m115-tenant}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_tenant_accounting_test"

cc -O2 -Wall -Wextra -Werror -Wno-cpp -Wno-deprecated-declarations -static \
  -I"$LINUX/include/uapi" -I"$LINUX/include" \
  "$LINUX/tools/testing/selftests/agi_tenant_accounting_test.c" -o "$TEST"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -sf busybox "$ROOTFS/bin/sh"
cp "$TEST" "$ROOTFS/bin/agi_tenant_accounting_test"
cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
printf 'FAISAL_M115_BOOT_OK\n'
[ -e /dev/agi_lifecycle ] || { echo M115_DEVICE_NODE_MISSING; exit 1; }
/bin/agi_tenant_accounting_test
rc=$?
printf 'M115_SELFTEST_RC=%s\n' "$rc"
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
for marker in FAISAL_M115_BOOT_OK M115_TENANT_BUDGET_SET_OK M115_TENANT_BUDGET_ADMISSION_DENY_OK M115_TENANT_BUDGET_QUERY_OK M115_TENANT_AGGREGATE_OK M115_TENANT_MALFORMED_REJECT_OK M115_TENANT_BUDGET_CLEAR_OK M115_SELFTEST_EXIT=0 M115_SELFTEST_RC=0; do
  grep -q "$marker" "$LOG"
done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then
  exit 1
fi
echo M115_TENANT_ACCOUNTING_QEMU_VALIDATION_OK
