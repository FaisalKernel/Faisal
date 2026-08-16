#!/bin/sh
set -eu
OUT=/home/ubuntu/agi-kernel/build/recovered
ROOT=/home/ubuntu/agi-kernel/build/qemu-faisal-execution-domain/rootfs
IMAGE=/home/ubuntu/agi-kernel/build/qemu-faisal-execution-domain/initramfs.cpio.gz
LOG=/home/ubuntu/agi-kernel/build/qemu-faisal-execution-domain/qemu.log
QEMU_ACCEL=${FAISAL_QEMU_ACCEL:-tcg,thread=single}
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/tmp"
cp "$(command -v busybox)" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
cp "$OUT/agi_execution_domain_test" "$ROOT/bin/agi_execution_domain_test"
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
printf 'FAISAL_M67_BOOT_OK\n'
/bin/agi_execution_domain_test
rc=$?
printf 'FAISAL_M67_TEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOT/init"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$IMAGE")
set +e
timeout 90s qemu-system-x86_64 -M pc -accel "$QEMU_ACCEL" -m 512M -smp 2 -kernel "$OUT/arch/x86/boot/bzImage" -initrd "$IMAGE" -append 'console=ttyS0 rdinit=/init' -nographic -no-reboot -monitor none -serial "file:$LOG" >/tmp/faisal-m67-qemu-stderr.log 2>&1
rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m67-qemu-stderr.log 2>/dev/null || true
printf 'QEMU_RC=%s\n' "$rc"
grep -q 'M67_SELFTEST_EXIT=0' "$LOG"
printf 'FAISAL_M67_SELFTEST_EXIT=0\n'
