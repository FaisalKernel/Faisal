from __future__ import annotations

import statistics
import time

from faisal_evidence_freshness import EvidenceFreshnessLedger, FreshnessPolicy, QualificationLease, QualificationSurface, digest

AUTHORITY = {
    "evidence_is_truth": False,
    "evidence_is_execution_authority": False,
    "evidence_is_policy_authority": False,
    "evidence_is_production_authority": False,
    "qualification_receipt_is_attestation": False,
}


def build():
    p = FreshnessPolicy("p", "v1", 7, 47, max_evidence_age=100, max_lease_ttl=120)
    s = QualificationSurface("s1", digest({"m": 1}), digest({"t": 1}), digest({"r": 1}), digest({"p": 1}), digest({"h": 1}), digest({"e": 1}), digest({"b": 1}), 47, 7)
    l = QualificationLease("lease", "q", s.surface_digest, digest({"evidence": 1}), digest({"prov": 1}), p.policy_digest, 7, 30, 20, 100, (), False)
    return p, s, l


def measure(fn, count=1000):
    samples = []
    for i in range(count):
        start = time.perf_counter_ns(); fn(i); samples.append(time.perf_counter_ns() - start)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]


def main():
    p, s, l = build()

    def baseline(i):
        return {"surface": s.surface_digest, "lease": l.lease_digest}

    def admit(i):
        policy, surface, lease = build(); return EvidenceFreshnessLedger(policy).admit(surface, lease, now=31, authority=AUTHORITY, nonce=f"n-{i}")

    def quarantine(i):
        policy, surface, lease = build(); ledger = EvidenceFreshnessLedger(policy); ledger.admit(surface, lease, now=31, authority=AUTHORITY, nonce=f"n-{i}"); return ledger.quarantine("lease")

    def revoke(i):
        policy, surface, lease = build(); ledger = EvidenceFreshnessLedger(policy); ledger.admit(surface, lease, now=31, authority=AUTHORITY, nonce=f"n-{i}"); return ledger.revoke("lease")

    for name, fn in (("baseline_ungoverned", baseline), ("freshness_admit", admit), ("quarantine", quarantine), ("revoke", revoke)):
        mean, p95 = measure(fn)
        print(f"FAISAL_EVIDENCE_FRESHNESS_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
