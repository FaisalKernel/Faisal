#include "faisal_plan_admission.h"

#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[FPA_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0;

	if ((!data && length) || !digest)
		return FPA_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FPA_ERR_TAMPER;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
	    (length && EVP_DigestUpdate(ctx, data, length) != 1) ||
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
	    digest_length != FPA_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return FPA_ERR_TAMPER;
	}
	EVP_MD_CTX_free(ctx);
	return FPA_OK;
}

int fpa_find_node(const struct fpa_plan *plan, uint32_t node_id,
		  uint32_t *index_out)
{
	uint32_t i;

	if (!plan || !index_out || node_id == 0)
		return FPA_ERR_ARGUMENT;
	for (i = 0; i < plan->node_count; i++) {
		if (plan->nodes[i].node_id == node_id) {
			*index_out = i;
			return FPA_OK;
		}
	}
	return FPA_ERR_DEPENDENCY;
}

int fpa_plan_digest(const struct fpa_plan *plan,
		   uint8_t digest[FPA_DIGEST_SIZE])
{
	struct fpa_plan copy;

	if (!plan || !digest)
		return FPA_ERR_ARGUMENT;
	copy = *plan;
	copy.reserved0 = 0;
	return digest_bytes(&copy, sizeof(copy), digest);
}

static int add_u64(uint64_t *total, uint64_t value)
{
	if (!total || UINT64_MAX - *total < value)
		return FPA_ERR_OVERFLOW;
	*total += value;
	return FPA_OK;
}

static int validate_node_shape(const struct fpa_plan *plan,
			       const struct fpa_node *node, uint32_t index)
{
	uint32_t dependency;

	if (!node || node->node_id == 0 || node->dependency_count > FPA_MAX_DEPENDENCIES ||
	    node->risk_ppm > 1000000U || node->duration_ns == 0 ||
	    node->cpu_budget_ns == 0 || node->cost_budget_micro == 0 ||
	    (node->flags & ~FPA_FLAGS_ALL) || node->reserved)
		return FPA_ERR_ARGUMENT;
	if (node->required_capability_mask & ~plan->available_capability_mask)
		return FPA_ERR_CAPABILITY;
	for (dependency = 0; dependency < node->dependency_count; dependency++) {
		uint32_t prior;
		uint32_t dependency_index;

		if (!node->dependency_ids[dependency] ||
		    node->dependency_ids[dependency] == node->node_id)
			return FPA_ERR_DEPENDENCY;
		if (fpa_find_node(plan, node->dependency_ids[dependency],
				  &dependency_index) != FPA_OK)
			return FPA_ERR_DEPENDENCY;
		(void)dependency_index;
		for (prior = 0; prior < dependency; prior++)
			if (node->dependency_ids[prior] == node->dependency_ids[dependency])
				return FPA_ERR_CONFLICT;
	}
	(void)index;
	return FPA_OK;
}

static int choose_ready_node(const struct fpa_plan *plan,
			     const uint32_t indegree[FPA_MAX_NODES],
			     const uint8_t selected[FPA_MAX_NODES],
			     uint32_t *index_out)
{
	uint32_t i;
	uint32_t best = UINT32_MAX;

	for (i = 0; i < plan->node_count; i++) {
		if (selected[i] || indegree[i] != 0)
			continue;
		if (best == UINT32_MAX || plan->nodes[i].priority > plan->nodes[best].priority ||
		    (plan->nodes[i].priority == plan->nodes[best].priority &&
		     plan->nodes[i].node_id < plan->nodes[best].node_id))
			best = i;
	}
	if (best == UINT32_MAX)
		return FPA_ERR_CYCLE;
	*index_out = best;
	return FPA_OK;
}

static void set_reason(struct fpa_admission *admission, const char *reason)
{
	if (!admission || !reason)
		return;
	(void)snprintf(admission->reason, sizeof(admission->reason), "%s", reason);
}

int fpa_validate_plan(const struct fpa_plan *plan, struct fpa_admission *out)
{
	uint32_t indegree[FPA_MAX_NODES] = { 0 };
	uint8_t selected[FPA_MAX_NODES] = { 0 };
	uint32_t topological_index[FPA_MAX_NODES] = { 0 };
	uint64_t total_cpu = 0;
	uint64_t total_cost = 0;
	uint64_t total_duration = 0;
	uint64_t critical_path = 0;
	uint64_t slack_min = UINT64_MAX;
	uint32_t highest_risk = 0;
	uint32_t i;
	int rc;

	if (!plan || !out)
		return FPA_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->objective_id = plan->objective_id;
	out->plan_generation = plan->plan_generation;
	out->admission_state = FPA_ADMISSION_REJECTED;
	if (plan->abi_version != FPA_ABI_VERSION || plan->reserved0 ||
	    plan->objective_id == 0 || plan->plan_generation == 0 ||
	    plan->deadline_ns == 0 || plan->cpu_budget_ns == 0 ||
	    plan->cost_budget_micro == 0 || plan->node_count == 0 ||
	    plan->node_count > FPA_MAX_NODES || (plan->flags & ~FPA_FLAGS_ALL)) {
		set_reason(out, "invalid plan header");
		out->violation_mask |= FPA_VIOLATION_EMPTY;
		return FPA_ERR_ARGUMENT;
	}
	for (i = 0; i < plan->node_count; i++) {
		uint32_t j;

		rc = validate_node_shape(plan, &plan->nodes[i], i);
		if (rc != FPA_OK) {
			set_reason(out, rc == FPA_ERR_CAPABILITY ?
				   "required capability unavailable" :
				   "invalid node or dependency");
			out->violation_mask |= rc == FPA_ERR_CAPABILITY ?
				FPA_VIOLATION_CAPABILITY : FPA_VIOLATION_CONFLICT;
			return rc;
		}
		for (j = 0; j < i; j++)
			if (plan->nodes[j].node_id == plan->nodes[i].node_id) {
				set_reason(out, "duplicate node identifier");
				out->violation_mask |= FPA_VIOLATION_CONFLICT;
				return FPA_ERR_CONFLICT;
			}
		if (plan->nodes[i].risk_ppm > highest_risk)
			highest_risk = plan->nodes[i].risk_ppm;
		if (plan->nodes[i].risk_ppm >= FPA_RISK_APPROVAL ||
		    (plan->nodes[i].flags & FPA_FLAG_IRREVERSIBLE)) {
			out->approval_node_mask |= 1ULL << i;
			out->approval_required = 1U;
		}
		if (plan->nodes[i].flags & FPA_FLAG_IRREVERSIBLE)
			out->irreversible_node_mask |= 1ULL << i;
		out->required_capability_mask |= plan->nodes[i].required_capability_mask;
		rc = add_u64(&total_cpu, plan->nodes[i].cpu_budget_ns);
		if (rc != FPA_OK)
			return rc;
		rc = add_u64(&total_cost, plan->nodes[i].cost_budget_micro);
		if (rc != FPA_OK)
			return rc;
		rc = add_u64(&total_duration, plan->nodes[i].duration_ns);
		if (rc != FPA_OK)
			return rc;
		for (j = 0; j < plan->nodes[i].dependency_count; j++) {
			uint32_t dependency_index;
			(void)fpa_find_node(plan, plan->nodes[i].dependency_ids[j],
					&dependency_index);
			indegree[i]++;
		}
	}
	out->total_cpu_budget_ns = total_cpu;
	out->total_cost_budget_micro = total_cost;
	out->total_duration_ns = total_duration;
	i = 0;
	while (i < plan->node_count) {
		uint32_t node_index;
		uint32_t dependency;
		uint64_t start = 0;

		rc = choose_ready_node(plan, indegree, selected, &node_index);
		if (rc != FPA_OK) {
			set_reason(out, "dependency cycle detected");
			out->violation_mask |= FPA_VIOLATION_CYCLE;
			return FPA_ERR_CYCLE;
		}
		selected[node_index] = 1U;
		out->topological_order[i] = plan->nodes[node_index].node_id;
		topological_index[i] = node_index;
		for (dependency = 0; dependency < plan->nodes[node_index].dependency_count;
		     dependency++) {
			uint32_t dependency_index = 0;
			if (fpa_find_node(plan, plan->nodes[node_index].dependency_ids[dependency],
					  &dependency_index) != FPA_OK)
				return FPA_ERR_DEPENDENCY;
			if (out->earliest_finish_ns[dependency_index] > start)
				start = out->earliest_finish_ns[dependency_index];
		}
		if (UINT64_MAX - start < plan->nodes[node_index].duration_ns)
			return FPA_ERR_OVERFLOW;
		out->earliest_finish_ns[node_index] =
			start + plan->nodes[node_index].duration_ns;
		if (out->earliest_finish_ns[node_index] > critical_path)
			critical_path = out->earliest_finish_ns[node_index];
		for (dependency = 0; dependency < plan->node_count; dependency++) {
			uint32_t child_dep;
			for (child_dep = 0; child_dep < plan->nodes[dependency].dependency_count;
			     child_dep++) {
				if (plan->nodes[dependency].dependency_ids[child_dep] ==
				    plan->nodes[node_index].node_id && indegree[dependency]) {
					indegree[dependency]--;
					break;
				}
			}
		}
		i++;
	}
	(void)topological_index;
	out->topological_count = i;
	out->critical_path_ns = critical_path;
	for (i = 0; i < plan->node_count; i++) {
		uint64_t slack = plan->deadline_ns > out->earliest_finish_ns[i] ?
			plan->deadline_ns - out->earliest_finish_ns[i] : 0;
		out->slack_ns[i] = slack;
		if (slack < slack_min)
			slack_min = slack;
	}
	out->slack_min_ns = slack_min;
	out->highest_risk_ppm = highest_risk;
	if (critical_path > plan->deadline_ns) {
		out->violation_mask |= FPA_VIOLATION_DEADLINE;
		set_reason(out, "critical path exceeds deadline");
		return FPA_ERR_LIMIT;
	}
	if (total_cpu > plan->cpu_budget_ns) {
		out->violation_mask |= FPA_VIOLATION_CPU_BUDGET;
		set_reason(out, "aggregate CPU budget exceeded");
		return FPA_ERR_BUDGET;
	}
	if (total_cost > plan->cost_budget_micro) {
		out->violation_mask |= FPA_VIOLATION_COST_BUDGET;
		set_reason(out, "aggregate cost budget exceeded");
		return FPA_ERR_BUDGET;
	}
	if (plan->flags & FPA_FLAG_MODEL_PROPOSAL)
		out->approval_required = 1U;
	if (out->approval_required) {
		out->violation_mask |= FPA_VIOLATION_APPROVAL;
		set_reason(out, "explicit approval required before execution");
		return FPA_ERR_APPROVAL;
	}
	out->admission_state = FPA_ADMISSION_ADMITTED;
	set_reason(out, "plan admitted; execution remains separately authorized");
	return fpa_plan_digest(plan, out->plan_digest);
}

int fpa_verify_admission(const struct fpa_plan *plan,
			 const struct fpa_admission *admission)
{
	struct fpa_admission expected;
	int rc;

	if (!plan || !admission)
		return FPA_ERR_ARGUMENT;
	rc = fpa_validate_plan(plan, &expected);
	if (rc != FPA_OK && rc != FPA_ERR_APPROVAL && rc != FPA_ERR_LIMIT &&
	    rc != FPA_ERR_BUDGET && rc != FPA_ERR_CAPABILITY &&
	    rc != FPA_ERR_CYCLE && rc != FPA_ERR_CONFLICT)
		return rc;
	if (memcmp(&expected, admission, sizeof(expected)) != 0)
		return FPA_ERR_TAMPER;
	return FPA_OK;
}
