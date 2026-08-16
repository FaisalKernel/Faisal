#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD="${BUILD:-$ROOT/build/recovered}"
ROOTFS="${ROOTFS:-$ROOT/build/qemu-faisal-runtime-verification}"
LOG="$ROOTFS/qemu.log"
TESTER="$BUILD/agi_runtime_verification_test"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static \
  -I"$LINUX/include/uapi" -I"$LINUX/tools/faisal-memory" \
  -I"$LINUX/tools/faisal-deploy" -I"$LINUX/tools/faisal-self-healing" \
  -I"$LINUX/tools/faisal-attestation" -I"$LINUX/tools/faisal-runtime-verification" \
  "$LINUX/tools/faisal-memory/faisal_memory_service.c" \
  "$LINUX/tools/faisal-deploy/faisal_deploy_supervisor.c" \
  "$LINUX/tools/faisal-self-healing/faisal_self_healing.c" \
  "$LINUX/tools/faisal-attestation/faisal_runtime_attestation.c" \
  "$LINUX/tools/faisal-runtime-verification/faisal_runtime_verification.c" \
  "$LINUX/tools/testing/selftests/agi_runtime_verification_test.c" \
  -o "$TESTER" -lcrypto -ldl -lpthread > "$ROOTFS/build.log" 2>&1
cp "$TESTER" "$ROOTFS/bin/agi_runtime_verification_test"
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
  echo FAISAL_M87_DEVICE_NODE_MISSING
  echo FAISAL_M87_TEST_RC=1
  poweroff -f
fi
echo FAISAL_M87_BOOT_OK
/bin/agi_runtime_verification_test
rc=$?
echo FAISAL_M87_TEST_RC=$rc
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
MEM="${QEMU_MEM:-768M}"
SMP="${QEMU_SMP:-2}"
qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -smp "$SMP" -m "$MEM" \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' -nographic -no-reboot > "$LOG" 2>&1 || true
grep -q 'FAISAL_M87_BOOT_OK' "$LOG"
grep -q 'M87_ATTESTATION_BOUND_OK' "$LOG"
grep -q 'M87_SIGNAL_MISMATCH_DENIAL_OK' "$LOG"
grep -q 'M87_RUNTIME_SIGNAL_BIND_OK' "$LOG"
grep -q 'M87_PROVIDER_GATE_DENIAL_OK' "$LOG"
grep -q 'M87_PAYLOAD_DIGEST_DENIAL_OK' "$LOG"
grep -q 'M87_SIGNATURE_DENIAL_OK' "$LOG"
grep -q 'M87_SIGNED_BUNDLE_VERIFY_OK' "$LOG"
grep -q 'M87_MODEL_AUTHORITY_DENIAL_OK' "$LOG"
grep -q 'M87_ATTESTED_REPAIR_CANARY_OK' "$LOG"
grep -q 'M87_CANARY_ROLLBACK_OK' "$LOG"
grep -q 'M87_SELFTEST_EXIT=0' "$LOG"
grep -q 'FAISAL_M87_TEST_RC=0' "$LOG"
printf '%s\n' 'M87_RUNTIME_VERIFICATION_QEMU_VALIDATION_OK'
