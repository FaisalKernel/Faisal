#!/usr/bin/env python3
import json
import os
import statistics
import sys
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(__file__))
from faisal_portable_memory import VerifiedArtifactCache, create_artifact, entry_id, issue_capability, rehydrate, verify_artifact

ITERATIONS = 1000

def make_entries():
    root = {"component": "episodic", "parent_ids": [], "created_at": "2026-08-19T00:00:00Z", "version": "1", "payload": {"text": "memory observation", "tags": ["benchmark"]}}
    root["id"] = entry_id(root)
    child = {"component": "semantic", "parent_ids": [root["id"]], "created_at": "2026-08-19T00:01:00Z", "version": "1", "payload": {"fact": "verified memory", "confidence": 0.9}}
    child["id"] = entry_id(child)
    return {"episodic": [root], "semantic": [child], "procedural": [], "working": [], "identity": []}

memory_key = Ed25519PrivateKey.generate()
cap_key = Ed25519PrivateKey.generate()
artifact = create_artifact(make_entries(), memory_key, artifact_id="benchmark")
capability = issue_capability(cap_key, audience="agent:benchmark", components=["episodic", "semantic"], permissions=["rehydrate"], expires_at=int(time.time()) + 600)

def baseline():
    return json.dumps({"episodic": artifact["components"]["episodic"], "semantic": artifact["components"]["semantic"]}, sort_keys=True, separators=(",", ":"))

def verified():
    verify_artifact(artifact, memory_key.public_key())
    return rehydrate(artifact, memory_key.public_key(), capability, cap_key.public_key(), audience="agent:benchmark")["projection_digest"]

cache = VerifiedArtifactCache(max_entries=4)
cache.verify(artifact, memory_key.public_key())

def cached_verified():
    return rehydrate(artifact, memory_key.public_key(), capability, cap_key.public_key(), audience="agent:benchmark", verification_cache=cache)["projection_digest"]

def measure(fn):
    samples = []
    result = None
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        result = fn()
        samples.append(time.perf_counter_ns() - start)
    return samples, result

base, base_result = measure(baseline)
secure, secure_result = measure(verified)
cached, cached_result = measure(cached_verified)
print(f"FAISAL_PORTABLE_MEMORY_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_PORTABLE_MEMORY_BASELINE_MEAN_NS={statistics.mean(base):.2f}")
print(f"FAISAL_PORTABLE_MEMORY_VERIFIED_REHYDRATION_MEAN_NS={statistics.mean(secure):.2f}")
print(f"FAISAL_PORTABLE_MEMORY_CACHED_REHYDRATION_MEAN_NS={statistics.mean(cached):.2f}")
print(f"FAISAL_PORTABLE_MEMORY_BASELINE_P95_NS={sorted(base)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_PORTABLE_MEMORY_VERIFIED_REHYDRATION_P95_NS={sorted(secure)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_PORTABLE_MEMORY_CACHED_REHYDRATION_P95_NS={sorted(cached)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_PORTABLE_MEMORY_UNCACHED_OVERHEAD_RATIO={statistics.mean(secure) / statistics.mean(base):.4f}")
print(f"FAISAL_PORTABLE_MEMORY_CACHED_OVERHEAD_RATIO={statistics.mean(cached) / statistics.mean(base):.4f}")
print(f"FAISAL_PORTABLE_MEMORY_VERIFIED_DIGEST={secure_result}")
print(f"FAISAL_PORTABLE_MEMORY_CACHED_DIGEST={cached_result}")
print("FAISAL_PORTABLE_MEMORY_BENCHMARK_SCOPE=local_signed_merkle_verify_and_scoped_rehydration_not_model_or_storage_latency")
