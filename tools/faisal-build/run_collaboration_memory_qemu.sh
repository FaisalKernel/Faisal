#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_COLLAB_ROOTFS:-$ROOT/build/qemu-faisal-m109-collab}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_collaboration_memory_test"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -I"$LINUX/tools/faisal-collab" -I"$LINUX/tools/faisal-memory-unified" \
  -I"$LINUX/tools/faisal-task" -I"$LINUX/tools/faisal-memory" -I"$LINUX/include/uapi" \
  "$LINUX/tools/testing/selftests/agi_collaboration_memory_test.c" \
  "$LINUX/tools/faisal-collab/faisal_collaboration_service.c" \
  "$LINUX/tools/faisal-memory-unified/faisal_unified_memory.c" \
  -lcrypto -o "$TEST"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -sf busybox "$ROOTFS/bin/sh"
cp "$TEST" "$ROOTFS/bin/agi_collaboration_memory_test"
cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
printf 'FAISAL_M109_BOOT_OK\n'
/bin/agi_collaboration_memory_test
rc=$?
printf 'M109_SELFTEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -m 512M -smp 1 \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot -monitor none -serial "file:$LOG" \
  >/tmp/faisal-m109-collab-qemu-stderr.log 2>&1
qemu_rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m109-collab-qemu-stderr.log 2>/dev/null || true
printf 'M109_QEMU_RC=%s\n' "$qemu_rc"
[ "$qemu_rc" -ne 124 ]
for marker in \
  FAISAL_M109_BOOT_OK \
  M109_DYNAMIC_FABRIC_OPEN_OK \
  M109_DYNAMIC_CAPABILITY_DISCOVERY_OK \
  M109_STRUCTURED_DELEGATION_EVIDENCE_CHALLENGE_ESCALATION_OK \
  M109_QUORUM_VOTE_OK \
  M109_AGENT_RECOVERY_REDISTRIBUTION_READY_OK \
  M109_UNIFIED_MEMORY_CLASSES_BACKEND_NEUTRAL_OK \
  M109_TEMPORAL_RELATIONSHIP_QUERY_ACCESS_CONTROL_OK \
  M109_CONFLICT_VERSION_FORGETTING_PROVENANCE_OK \
  M109_MEMORY_REPLAY_OK \
  M109_COLLAB_REPLAY_FAIL_CLOSED_OK \
  M109_SELFTEST_EXIT=0 \
  M109_SELFTEST_RC=0; do grep -q "$marker" "$LOG"; done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then exit 1; fi
echo M109_COLLABORATION_MEMORY_QEMU_VALIDATION_OK
