# FAISAL comparative-kernel research checkpoint

**Date:** 2026-08-16

## Official Linux scheduler documentation

Source: https://docs.kernel.org/scheduler/sched-ext.html

The official documentation states that `sched_ext` is a scheduler class whose behavior is defined by BPF programs. It can group CPUs, be switched on and off dynamically, and restore default scheduling when an error is detected, a runnable task stalls, or a SysRq safety action is invoked. It exposes a broad scheduling interface, but the documented BPF scheduler APIs do not have stability guarantees. FAISAL should therefore prefer a bounded, version-pinned AGI scheduling policy and retain a safe fallback rather than replacing the default scheduler unconditionally.

## Official Linux DAMON documentation

Source: https://docs.kernel.org/mm/damon/index.html

DAMON is documented as a kernel subsystem for efficient data-access monitoring and access-aware system operations. Its stated design goals are accuracy at DRAM-level memory management, low online overhead, scalability with memory size, tunability, and automated operation. FAISAL should build tensor/model-memory policy on top of measured access regions and existing Linux MM facilities rather than inventing unvalidated page semantics or claiming tensor awareness without workload evidence.

## Initial superiority strategy

“Beat all present kernels” must be decomposed into workload-specific acceptance criteria. The first comparison targets are: p99 inference scheduling latency under competing background work; agent/task admission and cancellation latency; memory-tier placement and reclaim overhead for large model-like mappings; verified effect latency and recovery correctness; high-concurrency IPC/event delivery; checkpoint/replay latency; and end-to-end long-horizon task completion under bounded policy. Each target requires a matched baseline, identical hardware/configuration, repeated trials, confidence intervals, and regression gates.

FAISAL must retain only changes that improve a measured target or provide a required correctness/security capability with an explicitly accepted cost. No claim of universal kernel superiority follows from a single benchmark.

## Official MLPerf Inference methodology

Source: https://mlcommons.org/benchmarks/inference-datacenter/

MLCommons describes MLPerf Inference: Datacenter as measuring how quickly systems process inputs and produce results using a trained model. It defines scenarios with standard load generation and scenario-specific metrics, including latency constraints and throughput metrics. FAISAL’s inference comparisons should therefore report both tail latency and throughput under defined load, rather than using a single average or an isolated microbenchmark.

## Documentation lookup note

The attempted official URL `https://docs.kernel.org/io_uring/index.html` returned 404 on 2026-08-16. No io_uring capability claim is based on that failed lookup. Any future FAISAL storage benchmark must first locate the current official io_uring documentation or source-level API definitions and record them before implementation.

## References

[1]: https://docs.kernel.org/scheduler/sched-ext.html — Linux extensible scheduler class documentation.

[2]: https://docs.kernel.org/mm/damon/index.html — Linux DAMON documentation.

[3]: https://mlcommons.org/benchmarks/inference-datacenter/ — MLCommons MLPerf Inference: Datacenter.

## Current kernel.org release snapshot

Source: https://www.kernel.org/ (accessed 2026-08-16)

The official kernel archive lists mainline `7.2-rc7`, stable `7.1.8`, and long-term lines including `6.18.44`, `6.12.103`, `6.6.151`, `6.1.182`, `5.15.215`, and `5.10.264`, with the displayed release dates in August 2026. FAISAL’s current base is `v7.2-rc7`, so the initial fair comparison should include an unmodified upstream `v7.2-rc7` build using the same toolchain and configuration, then a maintained stable/LTS comparison when the same workload and hardware are available. The release page is a snapshot; benchmark manifests must record the exact commit, config, compiler, firmware, microcode, hardware, and governor state.
