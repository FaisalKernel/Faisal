#include "../../faisal-inference/faisal_inference_contract.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "FIC_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void seed_objective(struct fic_objective *o)
{
	memset(o, 0, sizeof(*o));
	o->abi_version = FIC_ABI_VERSION;
	o->requested_phases = FIC_PHASE_BOTH;
	o->kv_tier_mask = FIC_KV_GPU | FIC_KV_HOST;
	o->route_flags = FIC_ROUTE_REQUIRE_KV_LOCALITY | FIC_ROUTE_FAIL_CLOSED;
	o->objective_id = 1001;
	o->tenant_id = 42;
	o->deadline_ns = 5000000000ULL;
	o->max_ttft_ns = 5000000ULL;
	o->max_itl_ns = 5000000ULL;
	o->max_cost_micro = 1000ULL;
	o->max_accelerator_memory_bytes = 1ULL << 30;
	o->required_hardware_mask = 1;
	o->required_locality_mask = 1;
	o->difficulty = 500;
	o->privacy_level = 1;
	strcpy(o->tenant, "tenant-42");
	strcpy(o->objective, "contract-test");
	o->model_digest[0] = 0x42;
	o->input_digest[0] = 0x19;
}

int main(void)
{
	struct fmr_router router;
	struct fmr_model local, remote;
	struct fic_service service;
	struct fic_objective o;
	struct fic_route_decision d, d2;
	struct fic_completion c;

	if (fmr_init(&router) != FMR_OK)
		return fail("router init", -1);
	if (fmr_register(&router, "local-provider", "fast-local", FMR_LOCAL,
		FMR_REASONING, 990000, 100, 10, 8192, 1, 1, 1, &local) != FMR_OK)
		return fail("local register", -1);
	if (fmr_register(&router, "cloud-provider", "remote-large", FMR_CLOUD,
		FMR_REASONING, 999000, 500, 100, 32768, 1, 1, 1, &remote) != FMR_OK)
		return fail("remote register", -1);
	if (fic_init(&service, &router) != FIC_OK)
		return fail("service init", -1);
	seed_objective(&o);
	if (fic_validate_objective(&o) != FIC_OK)
		return fail("valid objective rejected", -1);
	if (fic_admit_and_route(&service, &o, &d) != FIC_OK)
		return fail("admission", -1);
	if (d.admission_state != FIC_ADMITTED || d.model_id != local.model_id ||
		d.selected_phases != FIC_PHASE_BOTH || d.selected_kv_tier != FIC_KV_GPU ||
		!d.provenance_digest[0])
		return fail("route contract", -1);
	printf("FIC_ADMISSION_OK model=%llu phases=0x%x kv=0x%x seq=%llu\n",
		(unsigned long long)d.model_id, d.selected_phases, d.selected_kv_tier,
		(unsigned long long)d.decision_sequence);

	c.ttft_ns = d.estimated_ttft_ns;
	c.itl_ns = 1000;
	c.cost_micro = d.estimated_cost_micro;
	c.accelerator_memory_bytes = 1ULL << 20;
	c.completed_phases = FIC_PHASE_BOTH;
	c.observed_kv_tier = FIC_KV_GPU;
	c.authorized_result = 1;
	if (fic_record_completion(&service, &o, &d, &c) != FIC_OK ||
		d.admission_state != FIC_COMPLETED || d.violation_mask)
		return fail("successful completion", -1);
	printf("FIC_COMPLETION_OK ttft_ns=%llu cost_micro=%llu\n",
		(unsigned long long)c.ttft_ns, (unsigned long long)c.cost_micro);

	seed_objective(&o);
	o.objective_id = 1006;
	if (fic_admit_and_route(&service, &o, &d2) != FIC_OK)
		return fail("tamper admission", -1);
	d2.provenance_digest[0] ^= 0x80;
	if (fic_record_completion(&service, &o, &d2, &c) != FIC_ERR_TAMPER)
		return fail("provenance tamper accepted", -1);
	printf("FIC_PROVENANCE_TAMPER_REJECT_OK\n");

	seed_objective(&o);
	o.objective_id = 1002;
	o.max_ttft_ns = 1;
	if (fic_admit_and_route(&service, &o, &d2) == FIC_OK)
		return fail("SLO-infeasible route accepted", -1);
	printf("FIC_SLO_ADMISSION_REJECT_OK\n");

	seed_objective(&o);
	o.objective_id = 1003;
	if (fic_admit_and_route(&service, &o, &d2) != FIC_OK)
		return fail("violation admission", -1);
	c.ttft_ns = d2.estimated_ttft_ns;
	c.itl_ns = 1000;
	c.cost_micro = d2.estimated_cost_micro;
	c.accelerator_memory_bytes = 1ULL << 20;
	c.completed_phases = FIC_PHASE_BOTH;
	c.observed_kv_tier = FIC_KV_GPU;
	c.authorized_result = 0;
	if (fic_record_completion(&service, &o, &d2, &c) != FIC_ERR_SLO ||
		d2.admission_state != FIC_VIOLATED ||
		!(d2.violation_mask & FIC_VIOLATION_AUTHORITY))
		return fail("unauthorized result accepted", -1);
	printf("FIC_MODEL_OUTPUT_NOT_AUTHORITY_OK violations=0x%x\n",
		d2.violation_mask);

	seed_objective(&o);
	o.objective_id = 1004;
	o.reserved[0] = 1;
	if (fic_validate_objective(&o) == FIC_OK)
		return fail("reserved field accepted", -1);
	printf("FIC_RESERVED_FIELD_REJECT_OK\n");

	seed_objective(&o);
	o.objective_id = 1005;
	o.route_flags = FIC_ROUTE_REQUIRE_KV_LOCALITY;
	if (fic_validate_objective(&o) == FIC_OK)
		return fail("fail-open route accepted", -1);
	printf("FIC_FAIL_CLOSED_POLICY_REJECT_OK\n");
	printf("FIC_SELFTEST_EXIT=0\n");
	return 0;
}
