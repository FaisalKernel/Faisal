#!/bin/sh
# Build a clean, provenance-pinned FAISAL kernel output.
set -eu

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
BASE_BUILD=${FAISAL_BASE_BUILD:-$ROOT/build/recovered}
OUT=${FAISAL_REPRO_BUILD:-$ROOT/build/industry-repro}
BUILDER_ID=${FAISAL_BUILDER_ID:-local-builder}
BUILDER_HOST=${FAISAL_BUILDER_HOST:-local-build-host}

[ -r "$BASE_BUILD/.config" ] || { echo "missing base config: $BASE_BUILD/.config" >&2; exit 2; }
commit_epoch=$(git -C "$LINUX" show -s --format=%ct HEAD)
source_epoch=${SOURCE_DATE_EPOCH:-$commit_epoch}
case "$source_epoch" in ''|*[!0-9]*) echo 'SOURCE_DATE_EPOCH must be numeric' >&2; exit 2;; esac
build_timestamp=$(date -u -d "@$source_epoch" '+%a %b %e %H:%M:%S UTC %Y')

rm -rf "$OUT"
mkdir -p "$OUT"
cp "$BASE_BUILD/.config" "$OUT/.config"
make -C "$LINUX" O="$OUT" olddefconfig >/dev/null
export SOURCE_DATE_EPOCH="$source_epoch"
export KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP="$build_timestamp"
export KBUILD_BUILD_USER=faisal-builder
export KBUILD_BUILD_HOST=faisal-reproducible
make -C "$LINUX" O="$OUT" -j2 bzImage

cat > "$OUT/reproducible-build.env" <<EOF
SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
KBUILD_BUILD_VERSION=$KBUILD_BUILD_VERSION
KBUILD_BUILD_TIMESTAMP=$KBUILD_BUILD_TIMESTAMP
KBUILD_BUILD_USER=$KBUILD_BUILD_USER
KBUILD_BUILD_HOST=$KBUILD_BUILD_HOST
source_revision=$(git -C "$LINUX" rev-parse HEAD)
config_sha256=$(sha256sum "$OUT/.config" | awk '{print $1}')
builder_id=$BUILDER_ID
builder_host=$BUILDER_HOST
EOF
printf 'FAISAL_REPRODUCIBLE_KERNEL_BUILD_OK\noutput=%s\nsource_epoch=%s\n' "$OUT" "$SOURCE_DATE_EPOCH"
