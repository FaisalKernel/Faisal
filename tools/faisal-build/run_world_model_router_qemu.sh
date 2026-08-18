#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_WORLD_ROUTER_ROOTFS:-$ROOT/build/qemu-faisal-m110-world-router-hardened}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_world_model_router_test"
QEMU_SMP=${FAISAL_QEMU_SMP:-1}
QEMU_MEMORY=${FAISAL_QEMU_MEMORY:-768M}
QEMU_TIMEOUT_SECONDS=${FAISAL_QEMU_TIMEOUT_SECONDS:-180}
QEMU_ACPI=${FAISAL_QEMU_ACPI:-off}

case "$QEMU_ACPI" in
  on) QEMU_MACHINE='pc' ;;
  off) QEMU_MACHINE='pc,acpi=off' ;;
  *) echo 'FAISAL_QEMU_ACPI must be on or off' >&2; exit 2 ;;
esac

cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -I"$LINUX/tools/faisal-world-model" \
  -I"$LINUX/tools/faisal-model-router" \
  -I"$LINUX/include/uapi" \
  "$LINUX/tools/testing/selftests/agi_world_model_router_test.c" \
  "$LINUX/tools/faisal-world-model/faisal_world_model_service.c" \
  "$LINUX/tools/faisal-model-router/faisal_model_router.c" \
  -o "$TEST" -lcrypto -ldl -lpthread

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$TEST" "$ROOTFS/bin/agi_world_model_router_test"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/cat"
ln -s busybox "$ROOTFS/bin/mknod"
ln -s busybox "$ROOTFS/bin/mount"

cat > "$ROOTFS/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tmpfs -o mode=1777 none /tmp
echo FAISAL_M110_BOOT_OK
/bin/agi_world_model_router_test
rc=$?
echo M110_SELFTEST_RC=$rc
echo FAISAL_M110_TEST_COMPLETE
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )

set +e
timeout "${QEMU_TIMEOUT_SECONDS}s" qemu-system-x86_64 \
  -M "$QEMU_MACHINE" -accel tcg,thread=multi -cpu qemu64 \
  -m "$QEMU_MEMORY" -smp "$QEMU_SMP" \
  -kernel "$BUILD/arch/x86/boot/bzImage" \
  -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot \
  -monitor none -serial "file:$LOG" > "$ROOTFS/qemu-stderr.log" 2>&1 &
qemu_pid=$!
qemu_rc=124
deadline=$(( $(date +%s) + QEMU_TIMEOUT_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if grep -q 'FAISAL_M110_TEST_COMPLETE' "$LOG" 2>/dev/null; then
    kill -TERM "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_rc=0
    break
  fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    wait "$qemu_pid" 2>/dev/null
    qemu_rc=$?
    break
  fi
  sleep 1
done
if kill -0 "$qemu_pid" 2>/dev/null; then
  kill -TERM "$qemu_pid" 2>/dev/null || true
  wait "$qemu_pid" 2>/dev/null || true
fi
set -e
printf 'FAISAL_M110_QEMU_RC=%s\n' "$qemu_rc" >> "$LOG"
cat "$LOG"
cat "$ROOTFS/qemu-stderr.log" 2>/dev/null || true
[ "$qemu_rc" -ne 124 ]
for marker in FAISAL_M110_BOOT_OK M110_WORLD_STATE_OPEN_OK M110_OBSERVED_EXPECTED_DRIFT_ACTIONABLE_OK M110_WORLD_RECONCILIATION_RESOLVED_OK M110_WORLD_REPLAY_OK M110_WORLD_REPLAY_FAIL_CLOSED_OK M110_SMALL_TO_LARGE_ESCALATION_OK M110_LARGE_TO_SMALL_COST_AWARE_OK M110_PROVIDER_PRIVACY_LOCALITY_FILTER_OK M110_SELFTEST_EXIT=0 M110_SELFTEST_RC=0 FAISAL_M110_TEST_COMPLETE; do
  grep -q "$marker" "$LOG"
done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu:.*stall|rcu_preempt.*stall|RCU_GP_WAIT_FQS|kthread starved' "$LOG"; then
  echo FAISAL_M110_PROFILE_RESULT=blocked_rcu_or_kernel_diagnostic
  exit 1
fi
echo FAISAL_M110_PROFILE_RESULT=qualified
printf '%s\n' 'M110_WORLD_MODEL_ROUTER_QEMU_VALIDATION_OK'
