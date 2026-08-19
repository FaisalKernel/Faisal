from __future__ import annotations
import statistics
import time
from faisal_qualification_intake import CATEGORIES, QualificationClaim, QualificationLedger, QualificationPolicy, digest

AUTH = {"model_output_is_authority": False, "evidence_claim_is_authority": False, "qualification_receipt_is_production_authority": False, "production_approval": False}
HEAD = "a" * 40; TAG = "FAISAL-QUALIFICATION-FIXTURE"; ARTIFACT = digest({"artifact": "bzImage"}); SUITE = digest({"suite": "qualification-v1"})
POLICY = QualificationPolicy("p1", TAG, HEAD, ARTIFACT, 3, 10, 100, 2, 2, CATEGORIES)
CLAIM = QualificationClaim("claim", "independent_builder", "external_reference", TAG, HEAD, ARTIFACT, "issuer", "qualification-authority", digest({"e": 1}), digest({"a": 1}), 20, 90, verifier_id="verifier", verification_method="reference-check", builder_id="builder", independence_group="group", qualification_suite_digest=SUITE)

def sample(fn, iterations=1000):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort(); return statistics.mean(values), values[int(iterations * 0.95) - 1]

def main():
    def baseline(): digest({"category": CLAIM.category, "release_head": HEAD, "artifact": ARTIFACT, "issuer": CLAIM.issuer_id})
    def admit(): QualificationLedger(POLICY).admit(CLAIM, nonce="n", now=21, authority=AUTH)
    def status():
        ledger = QualificationLedger(POLICY); ledger.admit(CLAIM, nonce="n", now=21, authority=AUTH); ledger.status(now=21, authority=AUTH)
    for name, fn in (("baseline_ungoverned", baseline), ("claim_admission", admit), ("status_evaluation", status)):
        mean, p95 = sample(fn)
        print(f"FAISAL_QUALIFICATION_INTAKE_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
