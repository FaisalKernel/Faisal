#!/bin/sh
set -eu

ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_GRAPH_FAULT_ROOTFS:-$ROOT/build/qemu-faisal-graph-fault}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_lifecycle_graph_fault_test"
QEMU_SMP=${FAISAL_QEMU_SMP:-2}
QEMU_MEMORY=${FAISAL_QEMU_MEMORY:-768M}
QEMU_TIMEOUT_SECONDS=${FAISAL_QEMU_TIMEOUT_SECONDS:-240}
QEMU_ACPI=${FAISAL_QEMU_ACPI:-off}
QEMU_EXIT_ON_SUCCESS=${FAISAL_QEMU_EXIT_ON_SUCCESS:-1}

case "$QEMU_ACPI" in
  on) QEMU_MACHINE='pc' ;;
  off) QEMU_MACHINE='pc,acpi=off' ;;
  *) echo 'FAISAL_QEMU_ACPI must be on or off' >&2; exit 2 ;;
esac
case "$QEMU_EXIT_ON_SUCCESS" in
  0|1) : ;;
  *) echo 'FAISAL_QEMU_EXIT_ON_SUCCESS must be 0 or 1' >&2; exit 2 ;;
esac

cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -I"$LINUX/include/uapi" \
  "$LINUX/tools/testing/selftests/agi_lifecycle_graph_fault_test.c" \
  -o "$TEST"

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$TEST" "$ROOTFS/bin/agi_lifecycle_graph_fault_test"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/mount"
ln -s busybox "$ROOTFS/bin/cat"
ln -s busybox "$ROOTFS/bin/mknod"

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
  echo FAISAL_GRAPH_FAULT_DEVICE_NODE_MISSING
  echo FAISAL_GRAPH_FAULT_RC=1
  poweroff -f
fi
echo FAISAL_GRAPH_FAULT_BOOT_OK
/bin/agi_lifecycle_graph_fault_test
rc=$?
echo FAISAL_GRAPH_FAULT_RC=$rc
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )

set +e
if [ "$QEMU_EXIT_ON_SUCCESS" = 1 ]; then
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
    if grep -q 'FAISAL_GRAPH_FAULT_RC=0' "$LOG" 2>/dev/null; then
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
else
  timeout "${QEMU_TIMEOUT_SECONDS}s" qemu-system-x86_64 \
    -M "$QEMU_MACHINE" -accel tcg,thread=multi -cpu qemu64 \
    -smp "$QEMU_SMP" -m "$QEMU_MEMORY" \
    -kernel "$BUILD/arch/x86/boot/bzImage" \
    -initrd "$ROOTFS/initramfs.cpio.gz" \
    -append 'console=ttyS0 quiet' -nographic -no-reboot > "$LOG" 2>&1
  qemu_rc=$?
fi
set -e
printf 'FAISAL_GRAPH_FAULT_QEMU_RC=%s\n' "$qemu_rc" >> "$LOG"
[ "$qemu_rc" -ne 124 ]
grep -q 'FAISAL_GRAPH_FAULT_BOOT_OK' "$LOG"
grep -q 'FAISAL_GRAPH_FAULT_RC=0' "$LOG"
grep -q 'FAISAL_GRAPH_FAULT_OK' "$LOG"
if grep -Eq 'BUG:|Oops:|Kernel panic|WARNING:.*kernel|general protection fault|KASAN:|UBSAN:|rcu:.*stall|rcu_preempt.*stall|RCU_GP_WAIT_FQS|kthread starved' "$LOG"; then
  echo 'FAISAL_GRAPH_FAULT_DIAGNOSTIC_FOUND' >&2
  exit 1
fi
echo FAISAL_GRAPH_FAULT_QEMU_VALIDATION_OK
