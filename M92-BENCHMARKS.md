# FAISAL M92 Benchmarks

**Status:** Userspace key-provider hardening measurements collected

## Workload

The M92 selftest performs 261 malformed-input cases, four concurrent signer workers, one rotation worker, one revocation worker, and one bind/unbind worker. The provider begins with one key, rotates through three additional keys, executes 256 revocation attempts, and closes while a bound service is present.

## Results

| Run | Configuration | Result | Sign operations | Rotations | Revocations | Host wall time |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Strict host | Static `-Wall -Wextra -Werror` | Passed | 512 | 3 | 256 | Not used |
| QEMU final | Recovered FAISAL kernel | Passed | 1 | 3 | 256 | Not used |
| ASan + UBSan | Dynamic sanitizer build | Passed | 128 | 3 | 256 | Not used |
| TSan | Dynamic race-detector build | Passed | 510 | 3 | 256 | Not used |
| Smoke 1 | Normal QEMU | Passed | 512 | 3 | 256 | 7821 ms |
| Smoke 2 | Normal QEMU | Passed | 385 | 3 | 256 | 7535 ms |
| Smoke 3 | Normal QEMU | Passed | 256 | 3 | 256 | 7354 ms |

The three normal-smoke mean was **7570 ms**, rounded to the nearest millisecond. These are end-to-end host timings including static build, kernel boot, QEMU execution, and shutdown. They are not cryptographic operation latency measurements, are not compared with upstream Linux, and do not demonstrate a performance improvement.

## Regression results

The existing M90 provider-contract harness passed after mutex protection and internal lifetime-helper changes. The existing M91 provider-gate harness also passed and continued to report `provider=none status=1`, proving that M92 did not turn unsupported hardware metadata into authority.

## Interpretation and non-claims

The evidence demonstrates repeatable malformed-input rejection, bounded concurrent provider state transitions, service cleanup, and sanitizer-observed execution for the tested schedules. It does not prove race freedom, formal correctness, multi-service lifetime safety, hardware-backed key security, TPM/TEE integration, remote attestation, or production readiness.

## Reproduction

```bash
cd /home/ubuntu/agi-kernel/linux
BUILD=/home/ubuntu/agi-kernel/build/recovered \
ROOTFS=/home/ubuntu/agi-kernel/build/qemu-faisal-m92-key-provider-hardening \
tools/faisal-build/run_key_provider_hardening_qemu.sh
```

## References

[1]: `tools/faisal-build/evidence/m92-key-provider-hardening-smoke.tsv` — three timing runs.
[2]: `tools/faisal-build/evidence/m92-strict-run.log` — strict host run.
[3]: `tools/faisal-build/evidence/m92-asan-ubsan-run.log` — ASan/UBSan run.
[4]: `tools/faisal-build/evidence/m92-tsan-run.log` — TSan run.
[5]: `tools/faisal-build/evidence/m92-key-provider-hardening-validation.json` — machine-readable result.
