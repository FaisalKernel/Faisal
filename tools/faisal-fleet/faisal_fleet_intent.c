#include "faisal_fleet_intent.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static int node_index(const struct fle_service *s, uint64_t node_id)
{
	size_t i;
	for (i = 0; i < s->node_count; i++)
		if (s->nodes[i].node_id == node_id)
			return (int)i;
	return -1;
}

static int assignment_index(const struct fle_service *s, uint64_t assignment_id)
{
	size_t i;
	for (i = 0; i < s->assignment_count; i++)
		if (s->assignments[i].assignment_id == assignment_id)
			return (int)i;
	return -1;
}

static int nonempty(const char *value, size_t size)
{
	return value && value[0] && memchr(value, '\0', size) != NULL;
}

static int match_if_set(const char *wanted, const char *actual, size_t size)
{
	return !wanted[0] || (nonempty(actual, size) && strncmp(wanted, actual, size) == 0);
}

static int digest_present(const uint8_t digest[FLE_DIGEST_SIZE])
{
	size_t i;
	for (i = 0; i < FLE_DIGEST_SIZE; i++)
		if (digest[i])
			return 1;
	return 0;
}

static uint32_t node_score(const struct fle_node *node,
	const struct fle_intent *intent)
{
	uint64_t score = (uint64_t)node->health_ppm;
	if (intent->zone[0] && strcmp(intent->zone, node->zone) == 0)
		score += 1000000ULL;
	if (intent->rack[0] && strcmp(intent->rack, node->rack) == 0)
		score += 500000ULL;
	if (intent->fabric[0] && strcmp(intent->fabric, node->fabric) == 0)
		score += 250000ULL;
	if (intent->required_accelerator_mask &&
		(node->accelerator_mask & intent->required_accelerator_mask) ==
		intent->required_accelerator_mask)
		score += 100000ULL;
	if (intent->required_capability_mask &&
		(node->capability_mask & intent->required_capability_mask) ==
		intent->required_capability_mask)
		score += 100000ULL;
	if (node->free_cpu_millis > intent->required_cpu_millis)
		score += (node->free_cpu_millis - intent->required_cpu_millis) / 1000ULL;
	if (node->free_memory_bytes > intent->required_memory_bytes)
		score += (node->free_memory_bytes - intent->required_memory_bytes) /
			(1024ULL * 1024ULL * 1024ULL);
	return score > 0xffffffffULL ? 0xffffffffU : (uint32_t)score;
}

static int eligible(const struct fle_node *node, const struct fle_intent *intent,
	const uint64_t selected[FLE_MAX_GANG], uint32_t selected_count)
{
	uint32_t i;
	if (!node || !intent || node->state != FLE_STATE_READY ||
		node->health_ppm < 100000 ||
		node->free_cpu_millis < intent->required_cpu_millis ||
		node->free_memory_bytes < intent->required_memory_bytes ||
		(node->capability_mask & intent->required_capability_mask) !=
		intent->required_capability_mask ||
		(node->accelerator_mask & intent->required_accelerator_mask) !=
		intent->required_accelerator_mask ||
		node->accelerator_count < intent->required_accelerator_count ||
		!match_if_set(intent->zone, node->zone, sizeof(node->zone)) ||
		!match_if_set(intent->rack, node->rack, sizeof(node->rack)) ||
		!match_if_set(intent->fabric, node->fabric, sizeof(node->fabric)))
		return 0;
	for (i = 0; i < selected_count; i++)
		if (selected[i] == node->node_id)
			return 0;
	return 1;
}

static void evidence_digest(const struct fle_intent *intent,
	const struct fle_assignment *assignment, uint8_t out[FLE_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0U;
	uint32_t i;
	int ok = 1;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		ok = 0;
	if (ok && EVP_DigestUpdate(ctx, &intent->abi_version,
			   sizeof(intent->abi_version)) != 1)
		ok = 0;
	if (ok && EVP_DigestUpdate(ctx, &intent->objective_id,
			   sizeof(intent->objective_id)) != 1)
		ok = 0;
	if (ok && EVP_DigestUpdate(ctx, &intent->tenant_id,
			   sizeof(intent->tenant_id)) != 1)
		ok = 0;
	if (ok && EVP_DigestUpdate(ctx, &intent->agent_id,
			   sizeof(intent->agent_id)) != 1)
		ok = 0;
	if (ok && EVP_DigestUpdate(ctx, &intent->expected_node_generation,
			   sizeof(intent->expected_node_generation)) != 1)
		ok = 0;
	if (ok && EVP_DigestUpdate(ctx, intent->lineage_digest,
			   sizeof(intent->lineage_digest)) != 1)
		ok = 0;
	if (ok && EVP_DigestUpdate(ctx, intent->policy_digest,
			   sizeof(intent->policy_digest)) != 1)
		ok = 0;
	if (ok && EVP_DigestUpdate(ctx, &assignment->assignment_id,
			   sizeof(assignment->assignment_id)) != 1)
		ok = 0;
	if (ok && EVP_DigestUpdate(ctx, &assignment->placement_sequence,
			   sizeof(assignment->placement_sequence)) != 1)
		ok = 0;
	for (i = 0U; ok && i < assignment->selected_count; ++i)
		if (EVP_DigestUpdate(ctx, &assignment->selected_nodes[i],
				     sizeof(assignment->selected_nodes[i])) != 1)
			ok = 0;
	if (ok && EVP_DigestFinal_ex(ctx, out, &digest_length) != 1)
		ok = 0;
	if (!ok || digest_length != FLE_DIGEST_SIZE)
		memset(out, 0, FLE_DIGEST_SIZE);
	if (ctx != NULL)
		EVP_MD_CTX_free(ctx);
}

static int validate_selected_generation(const struct fle_service *s,
	const struct fle_intent *intent, const struct fle_assignment *assignment)
{
	uint32_t i;
	for (i = 0; i < assignment->selected_count; i++) {
		int idx = node_index(s, assignment->selected_nodes[i]);
		if (idx < 0 || s->nodes[idx].generation != intent->expected_node_generation)
			return FLE_ERR_STALE;
	}
	return FLE_OK;
}

int fle_init(struct fle_service *service, uint32_t policy_flags, uint64_t now_ns)
{
	if (!service || !policy_flags || (policy_flags & ~(FLE_POLICY_FAIL_CLOSED |
		FLE_POLICY_REQUIRE_LINEAGE | FLE_POLICY_REQUIRE_AUTHORITY |
		FLE_POLICY_REQUIRE_TOPOLOGY)))
		return FLE_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy_flags = policy_flags;
	service->next_assignment_id = 1;
	service->next_sequence = 1;
	service->now_ns = now_ns;
	return FLE_OK;
}

int fle_add_node(struct fle_service *service, const struct fle_node *node)
{
	if (!service || !node || !node->node_id || !node->generation ||
		!node->health_ppm || node->state != FLE_STATE_READY ||
		service->node_count >= FLE_MAX_NODES)
		return FLE_ERR_ARGUMENT;
	if (node_index(service, node->node_id) >= 0)
		return FLE_ERR_DUPLICATE;
	service->nodes[service->node_count++] = *node;
	return FLE_OK;
}

int fle_validate_intent(const struct fle_service *service,
	const struct fle_intent *intent)
{
	if (!service || !intent || intent->abi_version != FLE_ABI_VERSION ||
		!intent->objective_id || !intent->tenant_id || !intent->agent_id ||
		!intent->expected_node_generation || !intent->deadline_ns ||
		!intent->required_cpu_millis || !intent->required_memory_bytes ||
		!intent->gang_size || intent->gang_size > FLE_MAX_GANG ||
		!nonempty(intent->tenant, sizeof(intent->tenant)) ||
		!nonempty(intent->objective, sizeof(intent->objective)) ||
		(service->policy_flags & FLE_POLICY_REQUIRE_AUTHORITY && !intent->authorized) ||
		(service->policy_flags & FLE_POLICY_REQUIRE_LINEAGE &&
			!digest_present(intent->lineage_digest)) ||
		(service->policy_flags & FLE_POLICY_REQUIRE_TOPOLOGY &&
			!intent->zone[0] && !intent->rack[0] && !intent->fabric[0]))
		return FLE_ERR_POLICY;
	return FLE_OK;
}

int fle_place(struct fle_service *service, const struct fle_intent *intent,
	struct fle_assignment *out)
{
	struct fle_assignment assignment;
	uint32_t selected = 0;
	uint32_t i;
	int rc;

	if (!service || !intent || !out || service->assignment_count >= FLE_MAX_ASSIGNMENTS)
		return FLE_ERR_ARGUMENT;
	rc = fle_validate_intent(service, intent);
	if (rc != FLE_OK)
		return rc;
	memset(&assignment, 0, sizeof(assignment));
	while (selected < intent->gang_size) {
		int best = -1;
		uint32_t best_score = 0;
		for (i = 0; i < service->node_count; i++) {
			uint32_t score;
			if (!eligible(&service->nodes[i], intent,
				assignment.selected_nodes, selected))
				continue;
			score = node_score(&service->nodes[i], intent);
			if (best < 0 || score > best_score ||
				(score == best_score && service->nodes[i].node_id <
				 service->nodes[best].node_id)) {
				best = (int)i;
				best_score = score;
			}
		}
		if (best < 0)
			return FLE_ERR_NO_PLACEMENT;
		assignment.selected_nodes[selected++] = service->nodes[best].node_id;
		if (best_score > assignment.score)
			assignment.score = best_score;
	}
	assignment.selected_count = selected;
	assignment.assignment_id = service->next_assignment_id++;
	assignment.objective_id = intent->objective_id;
	assignment.tenant_id = intent->tenant_id;
	assignment.agent_id = intent->agent_id;
	assignment.placement_sequence = service->next_sequence++;
	assignment.recovery_sequence = 0;
	assignment.state = FLE_ASSIGN_PLACED;
	assignment.score = node_score(&service->nodes[node_index(service,
		assignment.selected_nodes[0])], intent);
	snprintf(assignment.reason, sizeof(assignment.reason),
		"placed objective=%llu agent=%llu gang=%u topology=%.16s/%.16s/%.16s lineage=1 authority=1",
		(unsigned long long)intent->objective_id,
		(unsigned long long)intent->agent_id, intent->gang_size,
		intent->zone, intent->rack, intent->fabric);
	evidence_digest(intent, &assignment, assignment.evidence_digest);
	service->assignments[service->assignment_count++] = assignment;
	*out = assignment;
	return FLE_OK;
}

int fle_fail_node(struct fle_service *service, uint64_t node_id,
	uint64_t generation)
{
	int idx;
	if (!service || !node_id)
		return FLE_ERR_ARGUMENT;
	idx = node_index(service, node_id);
	if (idx < 0)
		return FLE_ERR_NOT_FOUND;
	if (service->nodes[idx].generation != generation)
		return FLE_ERR_STALE;
	service->nodes[idx].state = FLE_STATE_FAILED;
	service->nodes[idx].generation++;
	return FLE_OK;
}

int fle_recover(struct fle_service *service, uint64_t assignment_id,
	const struct fle_intent *intent, struct fle_assignment *out)
{
	int aidx;
	struct fle_assignment old;
	struct fle_assignment recovered;
	uint32_t i;
	int rc;

	if (!service || !intent || !out)
		return FLE_ERR_ARGUMENT;
	rc = fle_validate_intent(service, intent);
	if (rc != FLE_OK)
		return rc;
	aidx = assignment_index(service, assignment_id);
	if (aidx < 0)
		return FLE_ERR_NOT_FOUND;
	old = service->assignments[aidx];
	if (old.objective_id != intent->objective_id || old.agent_id != intent->agent_id)
		return FLE_ERR_CONFLICT;
	if (!intent->authorized && (service->policy_flags & FLE_POLICY_REQUIRE_AUTHORITY))
		return FLE_ERR_AUTHORITY;
	if (validate_selected_generation(service, intent, &old) == FLE_OK)
		return FLE_ERR_CONFLICT;
	service->assignments[aidx].state = FLE_ASSIGN_RECOVERING;
	recovered = old;
	recovered.state = FLE_ASSIGN_RECOVERED;
	recovered.recovery_sequence = service->next_sequence++;
	recovered.selected_count = 0;
	recovered.score = 0;
	for (i = 0; i < service->node_count && recovered.selected_count < intent->gang_size; i++) {
		if (!eligible(&service->nodes[i], intent, recovered.selected_nodes,
			recovered.selected_count))
			continue;
		recovered.selected_nodes[recovered.selected_count++] = service->nodes[i].node_id;
		if (node_score(&service->nodes[i], intent) > recovered.score)
			recovered.score = node_score(&service->nodes[i], intent);
	}
	if (recovered.selected_count != intent->gang_size) {
		service->assignments[aidx] = old;
		return FLE_ERR_NO_PLACEMENT;
	}
	recovered.violation_mask = 0;
	snprintf(recovered.reason, sizeof(recovered.reason),
		"recovered objective=%llu agent=%llu from_assignment=%llu recovery=%llu",
		(unsigned long long)intent->objective_id,
		(unsigned long long)intent->agent_id,
		(unsigned long long)assignment_id,
		(unsigned long long)recovered.recovery_sequence);
	evidence_digest(intent, &recovered, recovered.evidence_digest);
	service->assignments[aidx] = recovered;
	*out = recovered;
	return FLE_OK;
}

int fle_query_assignment(const struct fle_service *service, uint64_t assignment_id,
	struct fle_assignment *out)
{
	int idx;
	if (!service || !out)
		return FLE_ERR_ARGUMENT;
	idx = assignment_index(service, assignment_id);
	if (idx < 0)
		return FLE_ERR_NOT_FOUND;
	*out = service->assignments[idx];
	return FLE_OK;
}

int fle_test_policy_boundaries(struct fle_service *service)
{
	struct fle_intent intent;
	if (!service)
		return FLE_ERR_ARGUMENT;
	memset(&intent, 0, sizeof(intent));
	intent.abi_version = FLE_ABI_VERSION;
	intent.objective_id = 1;
	intent.tenant_id = 1;
	intent.agent_id = 1;
	intent.expected_node_generation = 1;
	intent.deadline_ns = service->now_ns + 1;
	intent.required_cpu_millis = 1;
	intent.required_memory_bytes = 1;
	intent.gang_size = 1;
	strcpy(intent.tenant, "tenant");
	strcpy(intent.objective, "policy-test");
	if (fle_validate_intent(service, &intent) == FLE_OK)
		return FLE_ERR_POLICY;
	return FLE_OK;
}
