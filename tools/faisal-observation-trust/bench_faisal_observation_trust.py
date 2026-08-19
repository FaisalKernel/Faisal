#!/usr/bin/env python3
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from faisal_observation_trust import Observation, ObservationPolicy, admit_observation, assess_side_effect, frame_observation

ITERATIONS = 5000
policy = ObservationPolicy(allowed_domains=frozenset({"example.com"}), max_content_bytes=4096, max_redirects=1, max_pixels=10000, max_duration_ms=1000)
observation = Observation(observation_id="bench", source_type="browser_dom", source_uri="https://example.com/page", content_type="text/html", content="safe page data with no authority", byte_size=32, source_generation=4)


def baseline():
    return __import__("hashlib").sha256(observation.content.encode()).hexdigest()


def validated():
    receipt = admit_observation(observation, policy, expected_generation=4)
    framed = frame_observation(receipt, observation.content)
    decision = assess_side_effect(action="read", target=observation.source_uri, risk="low", capability_scopes={"side_effect:low"}, user_confirmation=False, observation_receipt=receipt)
    return receipt["observation_digest"], len(framed), decision["decision_digest"]


def measure(fn):
    samples = []
    result = None
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        result = fn()
        samples.append(time.perf_counter_ns() - start)
    return samples, result

base, base_result = measure(baseline)
checked, checked_result = measure(validated)
print(f"FAISAL_OBSERVATION_TRUST_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_OBSERVATION_TRUST_BASELINE_MEAN_NS={statistics.mean(base):.2f}")
print(f"FAISAL_OBSERVATION_TRUST_VALIDATED_MEAN_NS={statistics.mean(checked):.2f}")
print(f"FAISAL_OBSERVATION_TRUST_BASELINE_P95_NS={sorted(base)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_OBSERVATION_TRUST_VALIDATED_P95_NS={sorted(checked)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_OBSERVATION_TRUST_OVERHEAD_RATIO={statistics.mean(checked) / statistics.mean(base):.4f}")
print(f"FAISAL_OBSERVATION_TRUST_BASELINE_RESULT={base_result}")
print(f"FAISAL_OBSERVATION_TRUST_VALIDATED_RESULT={checked_result}")
print("FAISAL_OBSERVATION_TRUST_BENCHMARK_SCOPE=local_hash_vs_policy_admission_framing_and_side_effect_decision_not_browser_or_model_latency")
