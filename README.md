# FAISAL Kernel

FAISAL is a Linux-derived kernel and control-plane research platform for autonomous workloads that require explicit authority, provenance, recovery, and release-evidence boundaries. Complex reasoning and model execution remain in userspace; model output is not kernel or deployment authority.

## Release status

This public tree is based on the Linux 7.2 forward-port candidate `FAISAL-LINUX-7.2-FORWARDPORT-2026-08-19-R3`, with ABI `47`. It is a forward-port candidate, not a production release. Production authority remains fail-closed pending independent reproducible build evidence, an operator signing ceremony, physical hardware qualification, an independent external security review, and live multihost qualification.

## Scope

The tree includes the Linux-derived kernel source, FAISAL kernel and userspace control-plane components, build tooling, test and evidence tooling, required licensing material, and curated engineering documentation. Historical duplicate milestone reports and nonessential research notes are deliberately excluded from this public release branch.

## Licensing

This tree follows the Linux kernel licensing model. `COPYING` declares `SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note` and states that the kernel is under GNU General Public License version 2 only with an explicit Linux syscall exception. Kernel source files carry their applicable file-level SPDX license identifiers; the GPL-2.0 text and additional license texts and exceptions are provided under `LICENSES/`. Review file-level SPDX identifiers before redistributing or combining individual components.

## Build and validation

Use the kernel's standard Kbuild workflow. The public release retains the build and validation tooling needed to inspect the candidate and reproduce local checks. A successful local build or test run is not a production qualification claim.

## Security boundary

FAISAL does not grant authority from model output. Capability, intent, trace, checkpoint, routing, memory, and release-evidence records remain bounded by explicit policy and external approval requirements.
