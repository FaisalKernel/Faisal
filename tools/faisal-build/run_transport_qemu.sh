#!/bin/sh
set -eu
SRC=/home/ubuntu/agi-kernel/linux
OUT=/home/ubuntu/agi-kernel/build/recovered
ROOT=/home/ubuntu/agi-kernel/build/qemu-faisal-transport/rootfs
IMAGE=/home/ubuntu/agi-kernel/build/qemu-faisal-transport/initramfs.cpio.gz
LOG=/home/ubuntu/agi-kernel/build/qemu-faisal-transport/qemu.log
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/tmp"
if command -v busybox >/dev/null 2>&1; then BB=$(command -v busybox); else BB=/bin/busybox; fi
cp "$BB" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
cp "$OUT/agi_tensor_transport_test" "$ROOT/bin/agi_tensor_transport_test"
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
printf 'FAISAL_M66_BOOT_OK\n'
/bin/agi_tensor_transport_test
rc=$?
printf 'FAISAL_M66_TEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOT/init"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$IMAGE")
set +e
timeout 90s qemu-system-x86_64 -M pc -m 512M -kernel "$OUT/arch/x86/boot/bzImage" -initrd "$IMAGE" -append 'console=ttyS0 rdinit=/init' -nographic -no-reboot -monitor none -serial "file:$LOG" >/tmp/faisal-m66-qemu-stderr.log 2>&1
rc=$?
set -e
cat "$LOG"
printf 'QEMU_RC=%s\n' "$rc"
cat /tmp/faisal-m66-qemu-stderr.log 2>/dev/null || true
grep -q 'M66_SELFTEST_EXIT=0' "$LOG"
printf 'FAISAL_M66_SELFTEST_EXIT=0\n'
