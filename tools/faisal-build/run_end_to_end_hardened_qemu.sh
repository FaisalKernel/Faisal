#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_END_TO_END_ROOTFS:-$ROOT/build/qemu-faisal-end-to-end-hardened}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_end_to_end_test"
QEMU_SMP=${FAISAL_QEMU_SMP:-1}
QEMU_MEMORY=${FAISAL_QEMU_MEMORY:-768M}
QEMU_TIMEOUT_SECONDS=${FAISAL_QEMU_TIMEOUT_SECONDS:-240}
QEMU_ACPI=${FAISAL_QEMU_ACPI:-off}

case "$QEMU_ACPI" in
  on) QEMU_MACHINE='pc' ;;
  off) QEMU_MACHINE='pc,acpi=off' ;;
  *) echo 'FAISAL_QEMU_ACPI must be on or off' >&2; exit 2 ;;
esac

cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -I"$LINUX/include/uapi" \
  -I"$LINUX/tools/faisal-memory" -I"$LINUX/tools/faisal-experience" \
  -I"$LINUX/tools/faisal-world" -I"$LINUX/tools/faisal-orchestrator" \
  -I"$LINUX/tools/faisal-browser" -I"$LINUX/tools/faisal-coordinator" \
  "$LINUX/tools/faisal-memory/faisal_memory_service.c" \
  "$LINUX/tools/faisal-experience/faisal_experience_service.c" \
  "$LINUX/tools/faisal-world/faisal_world_state_service.c" \
  "$LINUX/tools/faisal-orchestrator/faisal_orchestrator_service.c" \
  "$LINUX/tools/faisal-browser/faisal_browser_tool_service.c" \
  "$LINUX/tools/faisal-coordinator/faisal_coordinator_service.c" \
  "$LINUX/tools/testing/selftests/agi_end_to_end_test.c" \
  -o "$TEST" -lcrypto -ldl -lpthread

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$TEST" "$ROOTFS/bin/agi_end_to_end_test"
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
if [ -r /sys/class/misc/agi_lifecycle/dev ]; then
  dev=$(cat /sys/class/misc/agi_lifecycle/dev)
  major=${dev%:*}
  minor=${dev#*:}
  mknod /dev/agi_lifecycle c "$major" "$minor" 2>/dev/null || true
fi
if [ ! -e /dev/agi_lifecycle ]; then
  echo FAISAL_M76_DEVICE_NODE_MISSING
  echo FAISAL_M76_TEST_RC=1
  echo FAISAL_M76_TEST_COMPLETE
  poweroff -f
fi
echo FAISAL_M76_BOOT_OK
/bin/agi_end_to_end_test
rc=$?
echo FAISAL_M76_TEST_RC=$rc
echo FAISAL_M76_TEST_COMPLETE
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )

set +e
timeout "${QEMU_TIMEOUT_SECONDS}s" qemu-system-x86_64 \
  -M "$QEMU_MACHINE" -accel tcg,thread=multi -cpu qemu64 \
  -smp "$QEMU_SMP" -m "$QEMU_MEMORY" \
  -kernel "$BUILD/arch/x86/boot/bzImage" \
  -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' -nographic -no-reboot > "$LOG" 2>&1 &
qemu_pid=$!
qemu_rc=124
deadline=$(( $(date +%s) + QEMU_TIMEOUT_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if grep -q 'FAISAL_M76_TEST_COMPLETE' "$LOG" 2>/dev/null; then
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
printf 'FAISAL_M76_QEMU_RC=%s\n' "$qemu_rc" >> "$LOG"
[ "$qemu_rc" -ne 124 ]
for marker in FAISAL_M76_BOOT_OK M76_TASK_INPUT_FUZZ_OK M76_TASK_INPUT_BOUNDARY_OK M76_INDEPENDENT_APPROVAL_DENIAL_OK M76_LONG_HORIZON_GRAPH_OK M76_MULTI_AGENT_IPC_OK M76_MONITORING_REFLECTION_OK M76_DEPLOYMENT_GATE_APPROVED_OK M76_FAILURE_RECOVERY_OK M76_SELFTEST_EXIT=0 FAISAL_M76_TEST_RC=0 FAISAL_M76_TEST_COMPLETE; do
  grep -q "$marker" "$LOG"
done
if grep -Eq 'BUG:|Oops:|Kernel panic|WARNING:.*kernel|general protection fault|KASAN:|KCSAN:|UBSAN:|rcu:.*stall|rcu_preempt.*stall|RCU_GP_WAIT_FQS|kthread starved|possible circular locking dependency|data-race|use-after-free|kernel BUG' "$LOG"; then
  echo FAISAL_M76_KERNEL_DIAGNOSTIC_FOUND >&2
  exit 1
fi
echo FAISAL_M76_QEMU_VALIDATION_OK
