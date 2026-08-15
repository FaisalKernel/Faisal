# FAISAL M79 Security Review

## Security scope

M79 is a provider-neutral userspace validation service. It does not add a device driver, open a physical accelerator, or infer hardware capability from the existence of a FAISAL context, tensor, telemetry, or power record.

## Threat model and controls

| Threat | M79 control | Residual limitation |
|---|---|---|
| Metadata claims a provider that is not present | Provider availability requires both `/dev/accel/accel0` and `/sys/class/accel/accel0`; absent evidence produces an explicit unsupported state | Provider-specific discovery and attestation remain future work |
| Over-broad device request | Kernel context negotiation returns active and unsupported masks; unsupported GPU/NPU/IO are retained rather than coerced to active | Hardware isolation requires a real provider test |
| Capability reuse | Context, tensor transport, and graph telemetry use returned capability handles; mutated handles must be denied | The selftest does not replace kernel fuzzing or race testing |
| Malformed provider metadata | State, name, masks, provider ID, flags, and reserved fields are bounded; 64 deterministic mutations are rejected | Full property-based fuzzing remains future work |
| Fake zero-copy or DMA claim | The test uses the existing bounded transport contract and does not report physical DMA success; provider availability remains separate | A real provider must validate DMA-buf/fence/device paths |
| Telemetry interpreted as hardware proof | Telemetry is reported as operation evidence only; provider-measured flags are not fabricated | Semantic and hardware correlation require provider tooling |
| Power request interpreted as applied hardware state | Applied and unsupported feature masks plus status are retained; the QEMU result shows CPU QoS applied and other requested features unsupported | Physical power/thermal behavior is provider-gated |
| Resource masking | Measured, unavailable, and unsupported masks are preserved separately | Provider-specific counters are unavailable without hardware |

## Security test conclusion

The QEMU selftest passes provider discovery, explicit unsupported-state handling, 64 metadata mutations, CPU-backed context and tensor validation, graph telemetry, resource-mask reporting, power-policy intent, and stale context/transport/telemetry capability denial. The results support only the demonstrated bounded contract. They do not establish real accelerator security, DMA isolation, IOMMU/SVA correctness, provider attestation, model performance, or physical power coordination.

## Non-fabrication boundary

M79 intentionally reports the current environment as unsupported. The absence of a provider is a valid result and is retained in evidence. Any later provider-specific milestone must include real device nodes, provider identity, negotiated features, isolation tests, resource measurements, transport completion, telemetry correlation, and power evidence before claiming accelerator support.
