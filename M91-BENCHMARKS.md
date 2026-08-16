# FAISAL M91 Benchmarks

**Status:** Unsupported-provider path measured and repeatable

## Workload

The M91 harness compiles a static provider-gate probe and boots the recovered FAISAL kernel in QEMU. The selftest sets a deliberately non-authoritative provider environment variable, probes observable device state, validates incomplete evidence denial, and requires an explicit unsupported or unverified result. It does not emulate a TPM, TEE, HSM, KMS, or hardware attestation protocol.

## Results

| Run | Provider result | Host wall time | Diagnostic findings |
| --- | --- | ---: | ---: |
| Smoke 1 | `provider=none status=1` | 5346 ms | 0 |
| Smoke 2 | `provider=none status=1` | 5275 ms | 0 |
| Smoke 3 | `provider=none status=1` | 5279 ms | 0 |

The mean host wall time was **5300 ms**, rounded to the nearest millisecond. These are end-to-end QEMU timings including build, boot, probe execution, and shutdown. They are not provider-operation latency measurements and are not a comparison against upstream Linux.

## Functional markers

The final run passed `M91_PROVIDER_PROBE_OK provider=none status=1 device_present=0`, `M91_ENV_METADATA_NOT_AUTHORITY_OK`, `M91_INCOMPLETE_EVIDENCE_DENIAL_OK`, `M91_HARDWARE_ATTESTATION_UNSUPPORTED_OK reason=no-provider`, `M91_SELFTEST_EXIT=0`, and `M91_TEST_RC=0`. No kernel warning, sanitizer, lockdep, or fault markers were present.

## Interpretation and non-claims

The results demonstrate that FAISAL can make the absence of a qualifying hardware/provider trust source observable and can refuse incomplete evidence. They do not demonstrate TPM, TEE, HSM, KMS, secure-boot, hardware attestation, key rotation, key revocation, hardware performance, or production readiness. The correct result for this environment is unsupported, not successful hardware integration.

## Reproduction

```bash
cd /home/ubuntu/agi-kernel/linux
BUILD=/home/ubuntu/agi-kernel/build/recovered \
ROOTFS=/home/ubuntu/agi-kernel/build/qemu-faisal-m91-provider-gate \
tools/faisal-build/run_provider_gate_qemu.sh
```

## References

[1]: `tools/faisal-build/evidence/m91-provider-gate-smoke.tsv` — three clean timing runs.
[2]: `tools/faisal-build/evidence/m91-provider-gate-qemu.log` — final provider classification output.
[3]: `tools/faisal-build/evidence/m91-provider-gate-validation.json` — machine-readable result.
[4]: `M91-PROVIDER-RESEARCH.md` — authoritative-source and local inspection notes.
