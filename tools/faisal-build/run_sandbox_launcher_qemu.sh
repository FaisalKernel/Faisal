#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_LAUNCHER_ROOTFS:-$ROOT/build/qemu-faisal-launcher}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_sandbox_launcher_test"
PROBE="$BUILD/faisal_launcher_probe"
FSL_CFLAGS=${FSL_CFLAGS:-}
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static $FSL_CFLAGS -I"$LINUX/tools/faisal-launcher" \
  "$LINUX/tools/faisal-launcher/faisal_sandbox_launcher.c" \
  "$LINUX/tools/testing/selftests/agi_sandbox_launcher_test.c" \
  -o "$TEST"
cc -nostdlib -static $FSL_CFLAGS -Wl,-e,_start \
  "$LINUX/tools/testing/faisal_launcher_probe.S" -o "$PROBE"
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS/bin" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"; ln -sf busybox "$ROOTFS/bin/sh"
cp "$TEST" "$ROOTFS/bin/agi_sandbox_launcher_test"
cp "$PROBE" "$ROOTFS/tmp/faisal_launcher_probe"
cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
printf 'FAISAL_M114_LAUNCHER_BOOT_OK\n'
/bin/agi_sandbox_launcher_test
rc=$?
printf 'M114_LAUNCHER_SELFTEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -m 512M -smp 1 \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot -monitor none \
  -serial "file:$LOG" >/tmp/faisal-m114-launcher-qemu-stderr.log 2>&1
qemu_rc=$?
set -e
cat "$LOG"; cat /tmp/faisal-m114-launcher-qemu-stderr.log 2>/dev/null || true
printf 'M114_LAUNCHER_QEMU_RC=%s\n' "$qemu_rc"
[ "$qemu_rc" -ne 124 ]
for marker in FAISAL_M114_LAUNCHER_BOOT_OK M114_TRUSTED_LAUNCHER_LANDLOCK_SECCOMP_OK M114_TRUSTED_LAUNCHER_CGROUP_FAIL_CLOSED_OK M114_LAUNCHER_SELFTEST_EXIT=0 M114_LAUNCHER_SELFTEST_RC=0; do grep -q "$marker" "$LOG"; done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then exit 1; fi
echo M114_SANDBOX_LAUNCHER_QEMU_VALIDATION_OK
