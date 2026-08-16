#include <stdio.h>
#include <string.h>
#include "../../faisal-autonomy/faisal_autonomy_orchestrator.h"

static int check(int condition, const char *marker)
{
	if (!condition) {
		fprintf(stderr, "M105_FAIL=%s\n", marker);
		return 1;
	}
	printf("%s\n", marker);
	return 0;
}

int main(void)
{
	struct m105_service service;
	struct m105_cycle cycle;
	int ret;

	ret = m105_open(&service, "/tmp/faisal-m105", "/dev/agi_lifecycle");
	if (check(ret == M105_OK, "M105_OPEN_OK"))
		return 1;
	ret = m105_observe_verify_learn(&service,
			"kernel.org publishes a signed Linux release",
			"https://example.test",
			"FAISAL primary source says the verified status is green.",
			"https://example.test",
			"FAISAL primary source says the verified status is green.",
			&cycle);
	if (check(ret == M105_OK && cycle.verified && cycle.promoted &&
			  cycle.experience_sequence != 0,
			  "M105_VERIFIED_OBSERVE_LEARN_OK")) {
		m105_close(&service);
		return 1;
	}
	if (check((cycle.evidence_mask & AGI_LC_AUTONOMY_EVIDENCE_OBSERVATION) != 0 &&
			  (cycle.evidence_mask & AGI_LC_AUTONOMY_EVIDENCE_SECURITY) != 0 &&
			  (cycle.evidence_mask & AGI_LC_AUTONOMY_EVIDENCE_TEST) != 0,
			  "M105_EVIDENCE_CHAIN_OK")) {
		m105_close(&service);
		return 1;
	}
	ret = m105_test_model_output_not_authority(&service);
	if (check(ret == M105_OK, "M105_MODEL_OUTPUT_NOT_AUTHORITY_OK")) {
		m105_close(&service);
		return 1;
	}
	if (check(service.cycle_count == 1, "M105_BOUNDED_CYCLE_ACCOUNTING_OK")) {
		m105_close(&service);
		return 1;
	}
	m105_close(&service);
	printf("M105_SELFTEST_EXIT=0\n");
	return 0;
}
