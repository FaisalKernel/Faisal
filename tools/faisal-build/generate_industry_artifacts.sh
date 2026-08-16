#!/bin/sh
# Generate independently inspectable FAISAL build metadata and an SPDX SBOM.
# This script does not claim a production signature unless a trusted signing key
# is explicitly supplied by the release environment.
set -eu

ROOT=${FAISAL_ROOT:-/home/ubuntu/agi-kernel}
LINUX=${FAISAL_LINUX:-$ROOT/linux}
BUILD=${FAISAL_BUILD:-$ROOT/build/recovered}
OUT=${FAISAL_ARTIFACT_OUT:-$BUILD/industry-artifacts}
mkdir -p "$OUT"
cd "$LINUX"

command -v sha256sum >/dev/null 2>&1 || { echo 'sha256sum is required' >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo 'git is required' >&2; exit 2; }

SOURCE_REV=$(git rev-parse HEAD)
SOURCE_TAG=$(git describe --tags --always --dirty)
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}
export SOURCE_DATE_EPOCH
CREATED=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
KERNEL_RELEASE=$(cat "$BUILD/include/config/kernel.release" 2>/dev/null || echo unknown)
CC_VERSION=$(cc --version 2>/dev/null | sed -n '1p' || echo unknown)
MAKE_VERSION=$(make --version 2>/dev/null | sed -n '1p' || echo unknown)
GIT_STATUS=$(git status --porcelain=v1 | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ')
CONFIG_SHA256=missing
if [ -r "$BUILD/.config" ]; then
  CONFIG_SHA256=$(sha256sum "$BUILD/.config" | awk '{print $1}')
fi

IMAGE="$BUILD/arch/x86/boot/bzImage"
VMLINUX="$BUILD/vmlinux"
MODULES_BUILT="$BUILD/modules.builtin"

hash_or_missing() {
  if [ -r "$1" ]; then sha256sum "$1" | awk '{print $1}'; else echo missing; fi
}

IMAGE_SHA256=$(hash_or_missing "$IMAGE")
VMLINUX_SHA256=$(hash_or_missing "$VMLINUX")
MODULES_SHA256=$(hash_or_missing "$MODULES_BUILT")
if [ -n "${FAISAL_SIGNING_KEY:-}" ]; then
  SIGNATURE_STATUS=detached-openssl-signatures-generated
else
  SIGNATURE_STATUS=unsigned-unless-release-environment-supplies-FAISAL_SIGNING_KEY
fi

MANIFEST="$OUT/FAISAL-build-manifest.json"
SBOM="$OUT/FAISAL-SBOM.spdx"
CHECKSUMS="$OUT/FAISAL-artifact-sha256sums.txt"

cat > "$MANIFEST" <<EOF
{
  "schema": "org.faisal.build-manifest.v1",
  "project": "FAISAL",
  "source_revision": "$SOURCE_REV",
  "source_description": "$SOURCE_TAG",
  "kernel_release": "$KERNEL_RELEASE",
  "kernel_base_declared": "Linux v7.2-rc7",
  "source_date_epoch": $SOURCE_DATE_EPOCH,
  "reproducibility_input": "SOURCE_DATE_EPOCH is pinned to the HEAD commit timestamp unless explicitly supplied",
  "compiler": "$CC_VERSION",
  "make": "$MAKE_VERSION",
  "config_sha256": "$CONFIG_SHA256",
  "artifacts": {
    "bzImage": {"path": "$IMAGE", "sha256": "$IMAGE_SHA256"},
    "vmlinux": {"path": "$VMLINUX", "sha256": "$VMLINUX_SHA256"},
    "modules_builtin": {"path": "$MODULES_BUILT", "sha256": "$MODULES_SHA256"}
  },
  "working_tree_status": "$GIT_STATUS",
  "signature_status": "$SIGNATURE_STATUS",
  "limitations": [
    "This manifest records provenance; it is not a cryptographic release attestation by itself.",
    "Independent rebuild comparison and trusted artifact signing remain release-gate requirements."
  ]
}
EOF

cat > "$CHECKSUMS" <<EOF
# FAISAL artifact checksums; generated with SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
$IMAGE_SHA256  $IMAGE
$VMLINUX_SHA256  $VMLINUX
$MODULES_SHA256  $MODULES_BUILT
$CONFIG_SHA256  $BUILD/.config
EOF

cat > "$SBOM" <<EOF
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: FAISAL-SBOM
DocumentNamespace: https://faisal.invalid/sbom/$SOURCE_REV
Creator: Tool: FAISAL generate_industry_artifacts.sh
Created: $CREATED

##### Packages #####
PackageName: FAISAL-kernel-source
SPDXID: SPDXRef-Package-FAISAL-source
PackageVersion: $SOURCE_REV
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION

PackageName: FAISAL-bzImage
SPDXID: SPDXRef-Package-FAISAL-bzImage
PackageVersion: $KERNEL_RELEASE
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION

##### Files #####
FileName: $IMAGE
SPDXID: SPDXRef-File-bzImage
FileChecksum: SHA256: $IMAGE_SHA256
LicenseConcluded: NOASSERTION
LicenseInfoInFile: NOASSERTION
FileCopyrightText: NOASSERTION

FileName: $VMLINUX
SPDXID: SPDXRef-File-vmlinux
FileChecksum: SHA256: $VMLINUX_SHA256
LicenseConcluded: NOASSERTION
LicenseInfoInFile: NOASSERTION
FileCopyrightText: NOASSERTION

FileName: $BUILD/.config
SPDXID: SPDXRef-File-config
FileChecksum: SHA256: $CONFIG_SHA256
LicenseConcluded: NOASSERTION
LicenseInfoInFile: NOASSERTION
FileCopyrightText: NOASSERTION

##### Relationships #####
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-FAISAL-source
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-FAISAL-bzImage
Relationship: SPDXRef-Package-FAISAL-bzImage CONTAINS SPDXRef-File-bzImage
Relationship: SPDXRef-Package-FAISAL-bzImage CONTAINS SPDXRef-File-vmlinux
Relationship: SPDXRef-Package-FAISAL-source CONTAINS SPDXRef-File-config
EOF

if [ -n "${FAISAL_SIGNING_KEY:-}" ]; then
  command -v openssl >/dev/null 2>&1 || { echo 'FAISAL_SIGNING_KEY supplied but openssl is unavailable' >&2; exit 2; }
  for artifact in "$MANIFEST" "$SBOM" "$CHECKSUMS"; do
    openssl dgst -sha256 -sign "$FAISAL_SIGNING_KEY" -out "$artifact.sig" "$artifact"
  done
else
  printf '%s\n' 'No FAISAL_SIGNING_KEY supplied; artifacts remain unsigned for this development audit.' >&2
fi

printf 'FAISAL_INDUSTRY_ARTIFACTS_OK\nmanifest=%s\nsbom=%s\nchecksums=%s\n' "$MANIFEST" "$SBOM" "$CHECKSUMS"
