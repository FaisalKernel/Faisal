#!/usr/bin/env python3
"""Prepare an external-builder handoff bundle; never claims the local builder is independent."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

ROOT = Path(os.environ.get("FAISAL_ROOT", "/home/ubuntu/agi-kernel"))
LTS = Path(os.environ.get("FAISAL_LTS_SOURCE", str(ROOT / "upstream/6.18.44/linux-6.18.44")))
BUILD = Path(os.environ.get("FAISAL_LTS_BUILD", str(ROOT / "build/faisal-lts-6.18.44")))
OUT = Path(os.environ.get("FAISAL_EXTERNAL_BUILDER_BUNDLE", str(ROOT / "build/m174-external-builder")))
REPO = ROOT / "linux"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


for required in (LTS / ".git", BUILD / ".config", REPO / "tools/faisal-build/build_reproducible_kernel.sh"):
    if not required.exists():
        raise SystemExit(f"required input missing: {required}")

OUT.mkdir(parents=True, exist_ok=True)
source_revision = subprocess.check_output(["git", "-C", str(LTS), "rev-parse", "HEAD"], text=True).strip()
epoch = subprocess.check_output(["git", "-C", str(LTS), "show", "-s", "--format=%ct", "HEAD"], text=True).strip()
bundle = OUT / "faisal-lts-source.bundle"
subprocess.run(["git", "-C", str(LTS), "bundle", "create", str(bundle), "HEAD"], check=True)
config = OUT / "faisal-lts.config"
shutil.copy2(BUILD / ".config", config)
recipe = OUT / "build_reproducible_kernel.sh"
shutil.copy2(REPO / "tools/faisal-build/build_reproducible_kernel.sh", recipe)
manifest = {
    "schema": "org.faisal.external-builder-handoff.v1",
    "generated_epoch": int(time.time()),
    "source": {
        "revision": source_revision,
        "source_date_epoch": int(epoch),
        "git_bundle": bundle.name,
        "git_bundle_sha256": sha256(bundle),
    },
    "configuration": {
        "file": config.name,
        "sha256": sha256(config),
        "required_config": ["CONFIG_CFS_BANDWIDTH=y"],
    },
    "build_recipe": {
        "file": recipe.name,
        "sha256": sha256(recipe),
        "toolchain_policy": "record compiler, binutils, linker, make, host kernel, container/VM identity, and package digests on the external builder",
    },
    "expected_outputs": [
        {"name": "bzImage", "path": "arch/x86/boot/bzImage", "digest_required": True},
        {"name": "vmlinux", "path": "vmlinux", "digest_required": True},
    ],
    "external_builder_requirements": {
        "builder_identity_evidence": "physical_host_measurement or provider_attestation",
        "independent_of_local_sandbox": True,
        "trusted_signer_builder_binding": True,
        "source_and_config_match": True,
        "artifact_subject_digest_match": True,
        "signed_build_log_digest": True,
        "sbom_or_dependency_manifest": True,
        "no_local_machine_id_or_container_identity": True,
    },
    "local_boundary": "This bundle is a handoff package only. Generation on this sandbox is not independent builder qualification.",
}
manifest_path = OUT / "external-builder-handoff.json"
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
readme = OUT / "EXTERNAL-BUILDER-INSTRUCTIONS.md"
readme.write_text(f"""# FAISAL external builder handoff\n\nBuild source revision `{source_revision}` with `SOURCE_DATE_EPOCH={epoch}` and the supplied `faisal-lts.config`. The builder must run on an independently governed host or trusted attested build platform. Record the builder ID, signer ID, host/VM or provider measurement, toolchain versions and digests, package/dependency inputs, build logs, SBOM, and SHA-256 digests of `arch/x86/boot/bzImage` and `vmlinux`.\n\nThe resulting signed report must use the existing `org.faisal.builder-attestation.v1` schema and set `builder_identity.evidence_type` to `physical_host_measurement` or `provider_attestation`. `container_machine_id`, `local_machine_id`, and self-reported identity are rejected. The external builder must independently verify the source revision, configuration digest, and artifact subjects before signing.\n\nThe local sandbox must not sign this report as an independent builder.\n""")
tar_path = OUT / "faisal-m174-external-builder-handoff.tar.gz"
with tarfile.open(tar_path, "w:gz") as archive:
    for path in (bundle, config, recipe, manifest_path, readme):
        archive.add(path, arcname=path.name)
print(f"FAISAL_EXTERNAL_BUILDER_BUNDLE_READY path={tar_path} source={source_revision}")
print(f"manifest={manifest_path}")
print(f"bundle_sha256={sha256(tar_path)}")
