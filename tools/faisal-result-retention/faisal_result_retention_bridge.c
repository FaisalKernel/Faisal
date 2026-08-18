#include "faisal_result_retention_bridge.h"

#include <string.h>

int rdr_import_fsv_result(struct rdr_service *retention,
			  const struct fsv_service *verification,
			  uint64_t result_id, const struct rdr_policy *policy,
			  struct rdr_event *out)
{
	struct fsv_record record;
	struct rdr_event event;
	int result;

	if (retention == NULL || verification == NULL || result_id == 0U ||
	    policy == NULL || out == NULL)
		return RDR_ERR_ARGUMENT;
	result = fsv_query_result(verification, result_id, &record);
	if (result != FSV_OK)
		return RDR_ERR_NOT_FOUND;
	if (record.state != FSV_STATE_VERIFIED &&
	    record.state != FSV_STATE_PROMOTED)
		return RDR_ERR_POLICY;
	if (record.receipt.decision != FSV_DECISION_VERIFIED &&
	    record.receipt.decision != FSV_DECISION_PROMOTED)
		return RDR_ERR_POLICY;
	memset(&event, 0, sizeof(event));
	event.result_id = record.request.result_id;
	event.receipt_id = record.receipt.receipt_id;
	event.tool_id = record.request.tool_id;
	event.tool_call_id = record.request.tool_call_id;
	event.objective_id = record.request.objective_id;
	event.trace_id = record.request.trace_id;
	event.agent_id = record.request.agent_id;
	event.tenant_id = record.request.tenant_id;
	event.task_generation = record.request.task_generation;
	event.session_generation = record.request.session_generation;
	event.world_generation = record.request.expected_world_generation;
	event.event_at_ns = record.request.observed_at_ns;
	event.expires_at_ns = record.request.deadline_ns;
	event.event_kind = RDR_EVENT_RESULT;
	event.flags = RDR_FLAG_VERIFIED;
	memcpy(event.result_digest, record.receipt.request_digest, RDR_DIGEST_SIZE);
	memcpy(event.payload_digest, record.request.payload_digest, RDR_DIGEST_SIZE);
	memcpy(event.provenance_digest, record.request.provenance_digest,
	       RDR_DIGEST_SIZE);
	return rdr_append_result(retention, &event, policy, out);
}

int rdr_commit_fsv_result(struct rdr_service *retention,
			  const struct fsv_service *verification,
			  uint64_t result_id,
			  const uint8_t transition_digest[RDR_DIGEST_SIZE],
			  const struct rdr_policy *policy, struct rdr_event *out)
{
	struct fsv_record record;
	int result;

	if (retention == NULL || verification == NULL || result_id == 0U ||
	    transition_digest == NULL || policy == NULL || out == NULL)
		return RDR_ERR_ARGUMENT;
	result = fsv_query_result(verification, result_id, &record);
	if (result != FSV_OK)
		return RDR_ERR_NOT_FOUND;
	if (record.state != FSV_STATE_PROMOTED ||
	    record.receipt.decision != FSV_DECISION_PROMOTED)
		return RDR_ERR_AUTHORITY;
	return rdr_append_transition(retention, result_id, RDR_EVENT_COMMIT,
			transition_digest, policy, out);
}
