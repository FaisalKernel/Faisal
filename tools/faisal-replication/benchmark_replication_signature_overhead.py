#!/usr/bin/env python3
"""Benchmark Ed25519 verification overhead in a controlled replication path."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import time
from pathlib import Path

import faisal_replication_pb2 as pb
from faisal_replication_providers import Ed25519RecordSignatureVerifier, Ed25519Signer, Ed25519TrustStore


def build_workload(count: int, payload_size: int):
    signer = Ed25519Signer.generate(7, 2, "benchmark-key", 1)
    store = Ed25519TrustStore({(7, 2, "benchmark-key", 1): signer.public_key_bytes()})
    verifier = Ed25519RecordSignatureVerifier(store)
    identity = signer.identity(1, count, b"\x00" * 32)
    previous = b"\x00" * 32
    records = []
    for sequence in range(1, count + 1):
        payload = hashlib.sha256(f"faisal-benchmark-{sequence}".encode()).digest()
        payload = (payload * ((payload_size + len(payload) - 1) // len(payload)))[:payload_size]
        digest = hashlib.sha256(previous + payload).digest()
        unsigned = pb.JournalRecord(sequence=sequence, previous_digest=previous, record_digest=digest, payload=payload)
        records.append(pb.JournalRecord(
            sequence=sequence,
            previous_digest=previous,
            record_digest=digest,
            payload=payload,
            record_signature=signer.sign_record(identity, unsigned),
        ))
        previous = digest
    return identity, records, verifier


def baseline(identity, records):
    previous = b"\x00" * 32
    accepted = 0
    for record in records:
        if record.previous_digest != previous:
            continue
        if hashlib.sha256(previous + bytes(record.payload)).digest() != bytes(record.record_digest):
            continue
        previous = bytes(record.record_digest)
        accepted += 1
    return accepted


def signed(identity, records, verifier):
    previous = b"\x00" * 32
    accepted = 0
    for record in records:
        if record.previous_digest != previous:
            continue
        if hashlib.sha256(previous + bytes(record.payload)).digest() != bytes(record.record_digest):
            continue
        if not verifier.verify(identity, record):
            continue
        previous = bytes(record.record_digest)
        accepted += 1
    return accepted


def measure(fn, repeats: int):
    samples = []
    accepted = None
    for _ in range(repeats):
        start = time.perf_counter_ns()
        accepted = fn()
        elapsed = time.perf_counter_ns() - start
        samples.append(elapsed)
    return accepted, samples


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=10000)
    parser.add_argument("--payload-bytes", type=int, default=256)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 100 <= args.records <= 1_000_000 or not 1 <= args.payload_bytes <= 1_048_576 or not 3 <= args.repeats <= 20:
        raise SystemExit("records, payload-bytes, or repeats outside bounded benchmark range")
    identity, records, verifier = build_workload(args.records, args.payload_bytes)
    baseline(identity, records[: min(100, args.records)])
    signed(identity, records[: min(100, args.records)], verifier)
    baseline_accepted, baseline_samples = measure(lambda: baseline(identity, records), args.repeats)
    signed_accepted, signed_samples = measure(lambda: signed(identity, records, verifier), args.repeats)
    baseline_median = statistics.median(baseline_samples)
    signed_median = statistics.median(signed_samples)
    result = {
        "benchmark": "faisal-replication-ed25519-overhead",
        "records": args.records,
        "payload_bytes": args.payload_bytes,
        "repeats": args.repeats,
        "accepted": {"baseline": baseline_accepted, "signed": signed_accepted},
        "baseline_median_ns": baseline_median,
        "signed_median_ns": signed_median,
        "baseline_records_per_second": args.records * 1_000_000_000 / baseline_median,
        "signed_records_per_second": args.records * 1_000_000_000 / signed_median,
        "verification_overhead_ns_per_record": (signed_median - baseline_median) / args.records,
        "verification_overhead_percent": ((signed_median / baseline_median) - 1.0) * 100.0,
        "baseline_samples_ns": baseline_samples,
        "signed_samples_ns": signed_samples,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
        },
        "interpretation": "Controlled host microbenchmark; not a claim of network, disk, KMS, TPM, secure-enclave, or production-cluster performance.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
