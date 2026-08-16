#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_ENGINEERING_ROOTFS:-$ROOT/build/qemu-faisal-m112-engineering}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_software_engineering_test"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread -I"$LINUX/tools/faisal-engineering" "$LINUX/tools/faisal-engineering/faisal_engineering_service.c" "$LINUX/tools/testing/selftests/agi_software_engineering_test.c" -o "$TEST"
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS/bin" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"; ln -sf busybox "$ROOTFS/bin/sh"; cp "$TEST" "$ROOTFS/bin/agi_software_engineering_test"
cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
printf 'FAISAL_M112_BOOT_OK\n'
/bin/agi_software_engineering_test
rc=$?
printf 'M112_SELFTEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -m 512M -smp 1 -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot -monitor none -serial "file:$LOG" >/tmp/faisal-m112-engineering-qemu-stderr.log 2>&1
qemu_rc=$?
set -e
cat "$LOG"; cat /tmp/faisal-m112-engineering-qemu-stderr.log 2>/dev/null || true
printf 'M112_QEMU_RC=%s\n' "$qemu_rc"
[ "$qemu_rc" -ne 124 ]
for marker in FAISAL_M112_BOOT_OK M112_ENGINEERING_SERVICE_OPEN_OK M112_REPOSITORY_REGISTRATION_OK M112_UNTRUSTED_CHANGE_PROPOSAL_OK M112_MODEL_OUTPUT_NOT_AUTHORITY_OK M112_REPOSITORY_DEPENDENCY_SECURITY_BUILD_TEST_DEBUG_PERF_REGRESSION_EVIDENCE_OK M112_VERIFICATION_GATE_OK M112_CANARY_OK M112_DEPLOY_APPROVAL_GATE_OK M112_ROLLBACK_OK M112_ENGINEERING_REPLAY_OK M112_ENGINEERING_REPLAY_FAIL_CLOSED_OK M112_SELFTEST_EXIT=0 M112_SELFTEST_RC=0; do grep -q "$marker" "$LOG"; done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then exit 1; fi
echo M112_SOFTWARE_ENGINEERING_QEMU_VALIDATION_OK
