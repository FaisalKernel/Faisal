#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_EXECUTION_ROOTFS:-$ROOT/build/qemu-faisal-durable-execution}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_durable_execution_test"

cc -O2 -Wall -Wextra -Werror -Wno-cpp -Wno-deprecated-declarations -pthread -static \
  -I"$LINUX/tools/faisal-task" -I"$LINUX/tools/faisal-execution" \
  -I"$LINUX/include/uapi" \
  "$LINUX/tools/testing/selftests/agi_durable_execution_test.c" \
  "$LINUX/tools/faisal-execution/faisal_execution_engine.c" \
  "$LINUX/tools/faisal-task/faisal_task_service.c" \
  -lcrypto -o "$TEST"

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -sf busybox "$ROOTFS/bin/sh"
ln -sf busybox "$ROOTFS/bin/mknod"
cp "$TEST" "$ROOTFS/bin/agi_durable_execution_test"
cat > "$ROOTFS/init" <<'INIT'
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
  printf 'M108_DEVICE_CREATE_FAIL\n'
  poweroff -f
fi
printf 'FAISAL_M108_BOOT_OK\n'
/bin/agi_durable_execution_test --require-kernel
rc=$?
printf 'M108_SELFTEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout 90s qemu-system-x86_64 \
  -M pc \
  -accel tcg,thread=multi \
  -cpu qemu64 \
  -m 512M \
  -smp 1 \
  -kernel "$BUILD/arch/x86/boot/bzImage" \
  -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 rdinit=/init quiet' \
  -nographic -no-reboot -monitor none -serial "file:$LOG" \
  >/tmp/faisal-m108-durable-execution-qemu-stderr.log 2>&1
qemu_rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m108-durable-execution-qemu-stderr.log 2>/dev/null || true
printf 'M108_QEMU_RC=%s\n' "$qemu_rc"
if [ "$qemu_rc" -eq 124 ]; then
  echo M108_QEMU_TIMEOUT >&2
  exit 1
fi

for marker in \
  FAISAL_M108_BOOT_OK \
  M108_KERNEL_SESSION_BIND_OK \
  M108_DURABLE_ENGINE_OPEN_OK \
  M108_INTENT_OBJECTIVE_CREATED_OK \
  M108_DAG_NODES_CREATED_OK \
  M108_INTENT_PLAN_DAG_EXECUTION_OK \
  M108_RETRY_BACKOFF_REROUTE_OK \
  M108_CHECKPOINT_SEALED_OK \
  M108_MODEL_OUTPUT_NOT_AUTHORITY_OK \
  M120_UNTRUSTED_HANDOFF_DIGEST_DENIED_OK \
  M120_CHECKPOINT_BOUND_HANDOFF_OK \
  M121_TAMPERED_HANDOFF_TOKEN_DENIED_OK \
  M122_STALE_HANDOFF_TOKEN_DENIED_OK \
  M123_OVERLONG_HANDOFF_LEASE_DENIED_OK \
  M125_RESTART_REPLAYED_HANDOFF_TOKEN_DENIED_OK \
  M126_JOURNAL_CHAIN_REPLAY_OK \
  M127_JOURNAL_SEQUENCE_POLICY_OK \
  M128_JOURNAL_ATTESTATION_RESTART_OK \
  M115_WORKER_TIMEOUT_REASSIGN_OK \
  M118_WORKER_QUARANTINE_OK \
  M115_POST_SUPERVISION_RECOVERY_IDEMPOTENT_OK \
  M115_WORKER_REPLAY_STATE_OK \
  M117_WORKER_HANDOFF_OK \
  M117_WORKER_HANDOFF_REPLAY_OK \
  M108_EXECUTION_REPLAY_OK \
  M108_CANCELLATION_COMPENSATION_BOUNDARY_OK \
  M108_ENGINE_REPLAY_FAIL_CLOSED_OK \
  M108_SELFTEST_EXIT=0 \
  M108_SELFTEST_RC=0; do
  grep -q "$marker" "$LOG"
done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then
  echo M108_DIAGNOSTIC_FAILURE >&2
  exit 1
fi
echo M108_DURABLE_EXECUTION_QEMU_VALIDATION_OK
