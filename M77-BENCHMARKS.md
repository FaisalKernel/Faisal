# FAISAL M77 Benchmarks and Measurement Limits

## Measurement scope

M77 timings cover QEMU boot, M75 scoped browser setup, M73 world-state setup, four bounded source collections, FAISAL knowledge publication and cross-check transitions, verified promotion, conflict denial, metadata fuzz checks, and shutdown. They do not measure internet latency, browser-engine performance, source-ranking quality, semantic truth, or model capability.

| Measurement | Result | Conditions |
|---|---:|---|
| Static selftest build | Pass | GCC strict warnings, static OpenSSL EVP linkage |
| QEMU smoke run 1 | 5.184186504 seconds | Two-vCPU QEMU, 768 MiB, BusyBox initramfs |
| QEMU smoke run 2 | 5.110059881 seconds | Same harness and environment |
| QEMU smoke run 3 | 5.237975044 seconds | Same harness and environment |
| QEMU smoke run 4 | 5.014599231 seconds | Same harness and environment |
| QEMU smoke run 5 | 5.156461234 seconds | Same harness and environment |
| QEMU smoke-run range | 5.0146–5.2380 seconds | Five runs; includes boot and shutdown |
| Metadata fuzz cases | 64 | Malformed source records rejected before knowledge publication |
| Required regression harnesses | 13/13 passed | M64 and M66–M77 |

## Interpretation

The measured wall time includes kernel boot, dynamic lifecycle-device discovery, static service startup, browser/world session initialization, persistent writes, kernel knowledge operations, and forced QEMU shutdown. It is an operational smoke measurement, not a research-quality latency benchmark. No baseline Linux or networked source-retrieval comparison was collected, so M77 makes no speed, efficiency, or freshness-latency claim.

The passing markers establish that the deterministic fixture can preserve source metadata, distinguish equal from conflicting content, require explicit verification, and promote only the verified fresh source into the M73 service. They do not establish that any external source is accurate or that a real-world research question was answered correctly.

## Future measurement work

A production research benchmark should separately measure network DNS/TLS/HTTP latency, browser action latency, parsing cost, digest cost, durable journal overhead, knowledge cross-check latency, conflict retention cost, world-state promotion cost, freshness revalidation latency, and concurrent source-query scalability. It should use fixed URLs, content snapshots, hardware, network conditions, and policy versions. Those measurements are not fabricated by M77.
