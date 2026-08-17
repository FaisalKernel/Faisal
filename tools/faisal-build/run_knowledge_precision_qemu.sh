#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_PRECISION_ROOTFS:-$ROOT/build/qemu-faisal-precision}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_knowledge_precision_test"

cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -I"$LINUX/include/uapi" \
  "$LINUX/tools/testing/selftests/agi_knowledge_precision_test.c" \
  -o "$TEST"
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS/bin" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"; ln -sf busybox "$ROOTFS/bin/sh"
cp "$TEST" "$ROOTFS/bin/agi_knowledge_precision_test"
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
printf 'FAISAL_M116_PRECISION_BOOT_OK\n'
/bin/agi_knowledge_precision_test
rc=$?
printf 'M116_PRECISION_SELFTEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -m 512M -smp 1 \
  -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" \
  -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot -monitor none \
  -serial "file:$LOG" >/tmp/faisal-m116-precision-qemu-stderr.log 2>&1
qemu_rc=$?
set -e
cat "$LOG"; cat /tmp/faisal-m116-precision-qemu-stderr.log 2>/dev/null || true
printf 'M116_PRECISION_QEMU_RC=%s\n' "$qemu_rc"
[ "$qemu_rc" -ne 124 ]
for marker in FAISAL_M116_PRECISION_BOOT_OK M116_PRECISION_UNVERIFIED_DENIAL_OK M116_PRECISION_CONFIDENCE_DENIAL_OK M116_PRECISION_FRESH_VERIFIED_OK M116_PRECISION_SELFTEST_EXIT=0 M116_PRECISION_SELFTEST_RC=0; do grep -q "$marker" "$LOG"; done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then exit 1; fi
echo M116_KNOWLEDGE_PRECISION_QEMU_VALIDATION_OK
