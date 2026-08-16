#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_WORLD_ROUTER_ROOTFS:-$ROOT/build/qemu-faisal-m110-world-router}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_world_model_router_test"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -I"$LINUX/tools/faisal-world-model" -I"$LINUX/tools/faisal-model-router" -I"$LINUX/include/uapi" \
  "$LINUX/tools/testing/selftests/agi_world_model_router_test.c" \
  "$LINUX/tools/faisal-world-model/faisal_world_model_service.c" \
  "$LINUX/tools/faisal-model-router/faisal_model_router.c" \
  -lcrypto -o "$TEST"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -sf busybox "$ROOTFS/bin/sh"
cp "$TEST" "$ROOTFS/bin/agi_world_model_router_test"
cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
printf 'FAISAL_M110_BOOT_OK\n'
/bin/agi_world_model_router_test
rc=$?
printf 'M110_SELFTEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -m 512M -smp 1 \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot -monitor none -serial "file:$LOG" \
  >/tmp/faisal-m110-world-router-qemu-stderr.log 2>&1
qemu_rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m110-world-router-qemu-stderr.log 2>/dev/null || true
printf 'M110_QEMU_RC=%s\n' "$qemu_rc"
[ "$qemu_rc" -ne 124 ]
for marker in FAISAL_M110_BOOT_OK M110_WORLD_STATE_OPEN_OK M110_OBSERVED_EXPECTED_DRIFT_ACTIONABLE_OK M110_WORLD_RECONCILIATION_RESOLVED_OK M110_WORLD_REPLAY_OK M110_WORLD_REPLAY_FAIL_CLOSED_OK M110_SMALL_TO_LARGE_ESCALATION_OK M110_LARGE_TO_SMALL_COST_AWARE_OK M110_PROVIDER_PRIVACY_LOCALITY_FILTER_OK M110_SELFTEST_EXIT=0 M110_SELFTEST_RC=0; do grep -q "$marker" "$LOG"; done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then exit 1; fi
echo M110_WORLD_MODEL_ROUTER_QEMU_VALIDATION_OK
