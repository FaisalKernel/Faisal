# FAISAL M90 Benchmarks

**Status:** Bounded functional and lifecycle measurements collected

## Workload

The M90 harness builds a static provider-bound selftest with the existing M87 memory, deployment, self-healing, attestation, and runtime-verification services. It generates two ephemeral Ed25519 keys, provisions the first, binds its public identity to M87, verifies a signed bundle, rotates to the second key, rejects the stale first bundle, tests independent approval denial, revokes the retired key, revokes the active key, and verifies fail-closed behavior.

## Results

| Run | Configuration | Result | Host wall time | Diagnostics |
| --- | --- | --- | ---: | ---: |
| Smoke 1 | Recovered FAISAL kernel, QEMU default | Passed | 8001 ms | 0 |
| Smoke 2 | Recovered FAISAL kernel, QEMU default | Passed | 7779 ms | 0 |
| Smoke 3 | Recovered FAISAL kernel, QEMU default | Passed | 7247 ms | 0 |
| Final contract run | Recovered FAISAL kernel | Passed; all M90 markers | Not used as benchmark | 0 |
| M87 regression after M90 | Recovered FAISAL kernel | Passed; all M87 markers | Not used as benchmark | 0 |

The three smoke-run mean was **7676 ms**, rounded to the nearest millisecond. These are end-to-end host timings for kernel boot, static binary construction, QEMU execution, and shutdown. They are not key-operation latency measurements, do not compare against upstream Linux, and do not demonstrate a performance improvement.

## Functional markers

The final M90 run passed `M90_KEY_PROVISION_OK`, `M90_PROVISIONED_BUNDLE_VERIFY_OK`, `M90_OLD_KEY_ISOLATION_OK`, `M90_KEY_ROTATION_OK`, `M90_INDEPENDENT_APPROVAL_DENIAL_OK`, `M90_OLD_KEY_REVOCATION_ISOLATED_OK`, `M90_REVOCATION_FAIL_CLOSED_OK`, `M90_SELFTEST_EXIT=0`, and `M90_TEST_RC=0`. The post-M90 M87 regression passed its original attestation, signal, provider, digest, signature, approval, canary, rollback, and exit markers.

## Interpretation and non-claims

The measurements demonstrate repeatable bounded execution of the userspace key-provider contract and compatibility of the existing M87 service test after adding key identity and generation fields to the signed digest. They do not demonstrate HSM or TPM performance, secure-boot provisioning, hardware-backed attestation, persistent secret-storage durability, distributed key quorum, formal cryptographic assurance, or production readiness.

## Reproduction

```bash
cd /home/ubuntu/agi-kernel/linux
BUILD=/home/ubuntu/agi-kernel/build/recovered \
ROOTFS=/home/ubuntu/agi-kernel/build/qemu-faisal-m90-key-provider \
tools/faisal-build/run_key_provider_qemu.sh
```

## References

[1]: `tools/faisal-build/evidence/m90-key-provider-smoke.tsv` — three clean timing runs.
[2]: `tools/faisal-build/evidence/m90-key-provider-qemu.log` — final provider-contract QEMU output.
[3]: `tools/faisal-build/evidence/m87-after-m90-qemu.log` — post-change M87 regression output.
[4]: `tools/faisal-build/evidence/m90-key-provider-validation.json` — machine-readable result.
