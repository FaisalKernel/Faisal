#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD="${BUILD:-$ROOT/build/recovered}"
ROOTFS="${ROOTFS:-$ROOT/build/qemu-faisal-m92-key-provider-hardening}"
LOG="$ROOTFS/qemu.log"
TESTER="$BUILD/agi_key_provider_hardening_test"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread \
  -I"$LINUX/include/uapi" -I"$LINUX/tools/faisal-runtime-verification" \
  -I"$LINUX/tools/faisal-key-provider" \
  "$LINUX/tools/faisal-key-provider/faisal_key_provider.c" \
  "$LINUX/tools/testing/selftests/agi_key_provider_hardening_test.c" \
  -o "$TESTER" -lcrypto > "$ROOTFS/build.log" 2>&1
cp "$TESTER" "$ROOTFS/bin/agi_key_provider_hardening_test"
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
echo M92_BOOT_OK
/bin/agi_key_provider_hardening_test
rc=$?
echo M92_TEST_RC=$rc
poweroff -f
EOF
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
MEM="${QEMU_MEM:-512M}"
SMP="${QEMU_SMP:-1}"
qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -smp "$SMP" -m "$MEM" \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 quiet' -nographic -no-reboot > "$LOG" 2>&1 || true
grep -q 'M92_BOOT_OK' "$LOG"
grep -q 'M92_MALFORMED_INPUTS_OK' "$LOG"
grep -q 'M92_CONCURRENT_STRESS_OK' "$LOG"
grep -q 'M92_SERVICE_LIFETIME_OK' "$LOG"
grep -q 'M92_SELFTEST_EXIT=0' "$LOG"
grep -q 'M92_TEST_RC=0' "$LOG"
if grep -Eq 'KASAN:|KCSAN:|BUG:|WARNING:|lockdep|data-race|use-after-free|deadlock|Oops|general protection fault|kernel BUG' "$LOG"; then
  echo M92_DIAGNOSTIC_FAILURE_MARKER
  exit 1
fi
printf '%s\n' 'M92_KEY_PROVIDER_HARDENING_QEMU_VALIDATION_OK'
