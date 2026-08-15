# FAISAL M75 Benchmarks and Measurement Limits

## Measurement scope

M75 measurements cover broker startup, capability and network-policy setup, browser-session lifecycle, semantic action recording, scope denials, hostile-content rejection, cancellation, durable action provenance, and QEMU shutdown. They do not measure browser-engine performance, web compatibility, model quality, prompt-injection completeness, or real-world task success.

| Measurement | Result | Conditions |
|---|---:|---|
| Static selftest build | Pass | GCC strict warnings, static OpenSSL EVP linkage |
| QEMU smoke run 1 | 5.055003293 seconds | Two-vCPU QEMU, 512 MiB, boot through forced poweroff |
| QEMU smoke run 2 | 5.029797016 seconds | Same harness and environment |
| QEMU smoke run 3 | 4.930867533 seconds | Same harness and environment |
| QEMU smoke run 4 | 5.189085193 seconds | Same harness and environment |
| QEMU smoke run 5 | 4.985733572 seconds | Same harness and environment |
| QEMU smoke-run range | 4.9309–5.1891 seconds | Five runs; includes boot and harness overhead |
| Malformed action cases | 64 | Invalid browser kind/reserved fields rejected |
| Required regression harnesses | 11/11 passed | M64 and M66–M75 |

## Interpretation

The QEMU wall times include kernel boot, initramfs construction, dynamic lifecycle-device discovery, static process startup, capability grant, network policy, browser actions, persistent-memory appends, cancellation, teardown, and shutdown. They are smoke timings only. No upstream Linux or browser-engine baseline was collected for M75, so no performance improvement or regression claim is made.

The markers establish that the broker exercised the kernel capability, network, browser, provenance, and cancellation contracts and that the deterministic policy denied out-of-scope and hostile inputs. They do not establish that a page is safe, that a browser action achieved its intended effect, or that prompt injection is solved.

## Future benchmark work

A production benchmark should separately measure capability grant latency, network-policy installation, browser-action ioctl latency, event delivery, durable provenance append, cancellation latency, scope-policy lookup, path-mediation overhead, browser-engine startup, DOM/accessibility extraction, screenshot capture, and tail latency under concurrent sessions. It should compare identical browser engines, runtime versions, hardware, policies, and workloads against an upstream Linux baseline. Those measurements are not fabricated by M75.
