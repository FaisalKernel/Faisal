from __future__ import annotations
import statistics
import time
from faisal_signing_ceremony import CeremonyEvent, CeremonyLedger, CeremonyPolicy, digest

AUTH = {"model_output_is_authority": False, "operator_claim_is_authority": False, "signature_receipt_is_production_authority": False, "production_approval": False}
POLICY = CeremonyPolicy("ceremony-1", "FAISAL-TEST-RELEASE", "a" * 40, digest({"artifact": "bzImage"}), "release", ("key-a", "key-b"), ("operator-a", "operator-b"), ("witness-a", "witness-b"), 2, 2, 4, 10, 100, "root-1")
EVENT = CeremonyEvent("event", "witness", "external_reference", "witness-a", "witness", POLICY.manifest_digest, digest({"event": 1}), 20, independence_group="witness-group")

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * 0.95) - 1]

def main():
    def baseline(): digest({"manifest": POLICY.manifest_digest, "artifact": POLICY.artifact_digest, "role": POLICY.role_id})
    def record(): CeremonyLedger(POLICY).record(EVENT, sequence=1, nonce="n", now=21, authority=AUTH)
    def status():
        ledger = CeremonyLedger(POLICY); ledger.record(EVENT, sequence=1, nonce="n", now=21, authority=AUTH); ledger.status(now=21, authority=AUTH)
    for name, fn in (("baseline_ungoverned", baseline), ("event_recording", record), ("status_evaluation", status)):
        mean, p95 = sample(fn)
        print(f"FAISAL_SIGNING_CEREMONY_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
