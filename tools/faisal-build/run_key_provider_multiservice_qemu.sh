#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD="${BUILD:-$ROOT/build/recovered}"
ROOTFS="${ROOTFS:-$ROOT/build/qemu-faisal-m93-key-provider-multiservice}"
LOG="$ROOTFS/qemu.log"
TESTER="$BUILD/agi_key_provider_multiservice_test"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -I"$LINUX/include/uapi" -I"$LINUX/tools/faisal-memory" \
  -I"$LINUX/tools/faisal-deploy" -I"$LINUX/tools/faisal-self-healing" \
  -I"$LINUX/tools/faisal-attestation" -I"$LINUX/tools/faisal-runtime-verification" \
  -I"$LINUX/tools/faisal-key-provider" \
  "$LINUX/tools/faisal-memory/faisal_memory_service.c" \
  "$LINUX/tools/faisal-deploy/faisal_deploy_supervisor.c" \
  "$LINUX/tools/faisal-self-healing/faisal_self_healing.c" \
  "$LINUX/tools/faisal-attestation/faisal_runtime_attestation.c" \
  "$LINUX/tools/faisal-runtime-verification/faisal_runtime_verification.c" \
  "$LINUX/tools/faisal-key-provider/faisal_key_provider.c" \
  "$LINUX/tools/testing/selftests/agi_key_provider_multiservice_test.c" \
  -o "$TESTER" -lcrypto -ldl -lpthread > "$ROOTFS/build.log" 2>&1
cp "$TESTER" "$ROOTFS/bin/agi_key_provider_multiservice_test"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
ln -s busybox "$ROOTFS/bin/sh"
ln -s busybox "$ROOTFS/bin/mount"
ln -s busybox "$ROOTFS/bin/cat"
ln -s busybox "$ROOTFS/bin/poweroff"
cat > "$ROOTFS/init" <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tmpfs -o mode=1777 none /tmp
echo M93_BOOT_OK
/bin/agi_key_provider_multiservice_test
rc=$?
echo M93_TEST_RC=$rc
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
MEM="${QEMU_MEM:-768M}"
SMP="${QEMU_SMP:-2}"
qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -smp "$SMP" -m "$MEM" \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' -nographic -no-reboot > "$LOG" 2>&1 || true
grep -q 'M93_BOOT_OK' "$LOG"
grep -q 'M93_MULTI_SERVICE_BIND_OK' "$LOG"
grep -q 'M93_SERVICE_CAPACITY_DENIAL_OK' "$LOG"
grep -q 'M93_REVOCATION_BROADCAST_OK' "$LOG"
grep -q 'M93_SAFE_SERVICE_CLOSE_OK' "$LOG"
grep -q 'M93_PROVIDER_CLOSE_CLEANUP_OK' "$LOG"
grep -q 'M93_CONTROLLED_RESTART_RECOVERY_OK' "$LOG"
grep -q 'M93_CONCURRENT_TABLE_STRESS_OK workers=8 iterations=64' "$LOG"
grep -q 'M93_PROCESS_CRASH_RECOVERY_NONCLAIM_OK' "$LOG"
grep -q 'M93_SELFTEST_EXIT=0' "$LOG"
grep -q 'M93_TEST_RC=0' "$LOG"
if grep -Eq 'KASAN:|KCSAN:|BUG:|WARNING:|lockdep|data-race|use-after-free|deadlock|Oops|general protection fault|kernel BUG' "$LOG"; then
  echo M93_DIAGNOSTIC_FAILURE_MARKER
  exit 1
fi
printf '%s\n' 'M93_KEY_PROVIDER_MULTISERVICE_QEMU_VALIDATION_OK'
