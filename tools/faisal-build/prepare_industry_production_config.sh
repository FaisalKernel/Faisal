#!/bin/sh
# Derive a production-oriented FAISAL configuration without mutating the
# validated development/recovery build. The resulting profile is an audit
# artifact; it is not a claim that QEMU alone proves production security.
set -eu

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
BASE_BUILD=${FAISAL_BASE_BUILD:-$ROOT/build/recovered}
OUT=${FAISAL_HARDENED_BUILD:-$ROOT/build/industry-production}
BASE_CONFIG="$BASE_BUILD/.config"

[ -r "$BASE_CONFIG" ] || { echo "missing base config: $BASE_CONFIG" >&2; exit 2; }
[ -x "$LINUX/scripts/config" ] || { echo 'scripts/config is unavailable' >&2; exit 2; }
mkdir -p "$OUT"
cp "$BASE_CONFIG" "$OUT/.config"

set_config() {
  "$LINUX/scripts/config" --file "$OUT/.config" "$@"
}

# Attack-surface reduction and kernel memory integrity.
set_config --enable CONFIG_BUG
set_config --enable CONFIG_DEBUG_WX
set_config --enable CONFIG_STRICT_KERNEL_RWX
set_config --enable CONFIG_STRICT_MODULE_RWX
set_config --enable CONFIG_STACKPROTECTOR_STRONG
set_config --enable CONFIG_HARDENED_USERCOPY
set_config --enable CONFIG_HARDENED_USERCOPY_DEFAULT_ON
set_config --enable CONFIG_FORTIFY_SOURCE
set_config --enable CONFIG_RANDOMIZE_BASE
set_config --enable CONFIG_RANDOMIZE_MEMORY
set_config --enable CONFIG_INIT_ON_ALLOC_DEFAULT_ON
set_config --enable CONFIG_INIT_ON_FREE_DEFAULT_ON
set_config --enable CONFIG_SLAB_FREELIST_HARDENED
set_config --enable CONFIG_SLAB_FREELIST_RANDOM
set_config --enable CONFIG_RANDOM_KMALLOC_CACHES
set_config --enable CONFIG_PAGE_TABLE_CHECK
set_config --enable CONFIG_PAGE_TABLE_CHECK_ENFORCED
set_config --enable CONFIG_VMAP_STACK
set_config --enable CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT
set_config --enable CONFIG_SECURITY_DMESG_RESTRICT
set_config --enable CONFIG_PROC_MEM_NO_FORCE
set_config --enable CONFIG_DEBUG_LIST
set_config --enable CONFIG_DEBUG_SG
set_config --enable CONFIG_DEBUG_VIRTUAL
set_config --enable CONFIG_BUG_ON_DATA_CORRUPTION
set_config --enable CONFIG_SCHED_STACK_END_CHECK
set_config --enable CONFIG_SYN_COOKIES
set_config --enable CONFIG_WERROR

# Narrow user/kernel and LSM attack surfaces while preserving the existing
# FAISAL capability model and SELinux-compatible LSM ordering.
set_config --enable CONFIG_SECCOMP
set_config --enable CONFIG_SECCOMP_FILTER
set_config --enable CONFIG_SECURITY
set_config --enable CONFIG_SECURITY_YAMA
set_config --enable CONFIG_SECURITY_LANDLOCK
set_config --enable CONFIG_SECURITY_LOCKDOWN_LSM
set_config --enable CONFIG_SECURITY_LOCKDOWN_LSM_EARLY
set_config --enable CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY
set_config --set-str CONFIG_LSM 'landlock,lockdown,yama,loadpin,safesetid,selinux,smack,tomoyo,apparmor,ipe,bpf'

# IOMMU strictness prevents stale device mappings where platform support exists.
set_config --enable CONFIG_IOMMU_SUPPORT
set_config --enable CONFIG_IOMMU_DEFAULT_DMA_STRICT

# Production attack-surface choices. FAISAL’s built-in lifecycle driver remains
# enabled; no runtime module loader or in-place kernel replacement is allowed.
set_config --disable CONFIG_MODULES
set_config --disable CONFIG_KEXEC
set_config --disable CONFIG_HIBERNATION
set_config --disable CONFIG_BINFMT_MISC
set_config --disable CONFIG_ACPI_CUSTOM_METHOD
set_config --disable CONFIG_DEVKMEM
set_config --disable CONFIG_PROC_KCORE
set_config --disable CONFIG_COMPAT

# Keep the release profile free of test-only instrumentation; dedicated KASAN,
# KCSAN, lockdep, KCOV, and KUnit builds remain separate audit profiles.
set_config --disable CONFIG_KASAN
set_config --disable CONFIG_KCSAN
set_config --disable CONFIG_KCOV
set_config --disable CONFIG_KUNIT
set_config --disable CONFIG_KFENCE
set_config --disable CONFIG_UBSAN
set_config --disable CONFIG_PROVE_LOCKING
set_config --disable CONFIG_LOCKDEP

make -C "$LINUX" O="$OUT" olddefconfig >/dev/null

cat > "$OUT/FAISAL-production-profile.txt" <<EOF
FAISAL production hardening profile
source_config=$BASE_CONFIG
output_config=$OUT/.config
kernel_base=Linux v7.2-rc7
modules=disabled
kexec=disabled
hibernation=disabled
landlock=enabled
lockdown=enabled-and-forced-confidentiality
seccomp=enabled
strict_iommu=enabled-where-platform-supports-it
test_instrumentation=disabled-in-release-profile
separate_audit_profiles=KASAN,KCSAN,KCOV,KUnit,lockdep
operator_gate=required
trusted_supervisor_gate=required
limitations=hardware-dependent controls and independent release signing require deployment environment evidence
EOF

printf 'FAISAL_INDUSTRY_PRODUCTION_CONFIG_OK\nconfig=%s\nprofile=%s\n' "$OUT/.config" "$OUT/FAISAL-production-profile.txt"
