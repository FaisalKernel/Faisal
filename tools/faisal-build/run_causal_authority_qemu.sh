#!/bin/sh
set -eu

OUT=${BUILD:-/home/ubuntu/agi-kernel/build/recovered}
ROOT=${ROOTFS:-/home/ubuntu/agi-kernel/build/qemu-faisal-m96-causal/rootfs}
IMAGE=${IMAGE:-/home/ubuntu/agi-kernel/build/qemu-faisal-m96-causal/initramfs.cpio.gz}
LOG=${LOG:-/home/ubuntu/agi-kernel/build/qemu-faisal-m96-causal/qemu.log}
SELFTEST=${SELFTEST:-/home/ubuntu/agi-kernel/build/m96/agi_causal_authority_test}
rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/tmp"
cp "$(command -v busybox)" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
ln -sf busybox "$ROOT/bin/mknod"
cp "$SELFTEST" "$ROOT/bin/agi_causal_authority_test"
cat > "$ROOT/init" <<'INIT'
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
  printf 'FAISAL_M96_DEVICE_NODE_MISSING\n'
  printf 'FAISAL_M96_TEST_RC=1\n'
  poweroff -f
fi
printf 'FAISAL_M96_BOOT_OK\n'
/bin/agi_causal_authority_test --require-kernel
rc=$?
printf 'FAISAL_M96_TEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOT/init"
mkdir -p "$(dirname "$IMAGE")" "$(dirname "$LOG")"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$IMAGE")
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 \
	-m 512M -smp "${QEMU_SMP:-1}" -kernel "$OUT/arch/x86/boot/bzImage" \
	-initrd "$IMAGE" -append 'console=ttyS0 rdinit=/init quiet' \
	-nographic -no-reboot -monitor none -serial "file:$LOG" \
	>/tmp/faisal-m96-causal-qemu-stderr.log 2>&1
rc=$?
set -e
cat "$LOG"
cat /tmp/faisal-m96-causal-qemu-stderr.log 2>/dev/null || true
printf 'QEMU_RC=%s\n' "$rc"
[ "$rc" -eq 0 ]
for marker in \
	FAISAL_M96_BOOT_OK \
	M96_CAUSAL_SERVICE_OPEN_OK \
	M96_AUTHORITY_REFERENCE_OK \
	M96_CAUSAL_BRANCH_PROPOSE_OK \
	M96_CAUSAL_PREPARE_AUTHORIZED_OK \
	M96_INCOMPLETE_COMMIT_REJECTED_OK \
	M96_EVIDENCE_COMPLETE_COMMIT_OK \
	M96_BRANCH_INVALIDATION_OK \
	M96_CAUSAL_REPLAY_OK \
	M96_CAUSAL_CORRUPTION_FAIL_CLOSED_OK \
	M96_SELFTEST_EXIT=0 \
	FAISAL_M96_TEST_RC=0; do
	grep -q "$marker" "$LOG"
done
if grep -Eq 'KASAN:|KCSAN:|data-race|BUG:|Oops:|Kernel panic|Call Trace' "$LOG"; then
	printf 'M96_KERNEL_DIAGNOSTIC_FOUND\n'
	exit 1
fi
printf 'FAISAL_M96_CAUSAL_AUTHORITY_QEMU_PASS\n'
