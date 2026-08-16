#!/bin/sh
set -eu
ROOT=/home/ubuntu/agi-kernel
LINUX="$ROOT/linux"
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
ROOTFS=${FAISAL_REPO_ADAPTER_ROOTFS:-$ROOT/build/qemu-faisal-m113-repo}
LOG="$ROOTFS/qemu.log"
TEST="$BUILD/agi_repository_adapter_test"
cc -O2 -Wall -Wextra -Werror -Wno-cpp -static -pthread -I"$LINUX/tools/faisal-repo-adapter" "$LINUX/tools/faisal-repo-adapter/faisal_repo_adapter.c" "$LINUX/tools/testing/selftests/agi_repository_adapter_test.c" -o "$TEST" -lcrypto
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS/bin" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/tmp"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"; ln -sf busybox "$ROOTFS/bin/sh"; cp "$TEST" "$ROOTFS/bin/agi_repository_adapter_test"
cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
printf 'FAISAL_M113_BOOT_OK\n'
/bin/agi_repository_adapter_test
rc=$?
printf 'M113_SELFTEST_RC=%s\n' "$rc"
poweroff -f
INIT
chmod +x "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$ROOTFS/initramfs.cpio.gz" )
set +e
timeout 90s qemu-system-x86_64 -M pc -accel tcg,thread=multi -cpu qemu64 -m 512M -smp 1 -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$ROOTFS/initramfs.cpio.gz" -append 'console=ttyS0 rdinit=/init quiet' -nographic -no-reboot -monitor none -serial "file:$LOG" >/tmp/faisal-m113-repo-qemu-stderr.log 2>&1
qemu_rc=$?
set -e
cat "$LOG"; cat /tmp/faisal-m113-repo-qemu-stderr.log 2>/dev/null || true
printf 'M113_QEMU_RC=%s\n' "$qemu_rc"
[ "$qemu_rc" -ne 124 ]
for marker in FAISAL_M113_BOOT_OK M113_REAL_REPOSITORY_ANALYSIS_OK M113_FILE_DIGEST_PROVENANCE_OK M113_PATH_AND_WORKSPACE_POLICY_OK M113_BOUNDED_CODE_STAGING_OK M113_WORKSPACE_ROLLBACK_OK M113_REPOSITORY_REPLAY_OK M113_REPOSITORY_REPLAY_FAIL_CLOSED_OK M113_SELFTEST_EXIT=0 M113_SELFTEST_RC=0; do grep -q "$marker" "$LOG"; done
if grep -Eq 'BUG:|Oops:|kernel panic|KASAN:|KCSAN:|WARNING:.*kernel|general protection fault|unable to handle kernel|possible circular locking dependency|data-race|use-after-free|kernel BUG|rcu: .*stall' "$LOG"; then exit 1; fi
echo M113_REPOSITORY_ADAPTER_QEMU_VALIDATION_OK
