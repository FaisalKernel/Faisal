#include "../../faisal-recovery/faisal_recovery_decision.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *name, int rc)
{
	fprintf(stderr, "M231_FAIL:%s rc=%d\n", name, rc);
	return 1;
}

static void fill_digest(uint8_t digest[FRD_DIGEST_SIZE], uint8_t value)
{
	unsigned int i;

	for (i = 0; i < FRD_DIGEST_SIZE; i++)
		digest[i] = value;
}

static void base_input(struct frd_input *input, uint64_t sequence)
{
	memset(input, 0, sizeof(*input));
	input->request_sequence = sequence;
	input->now_ns = 100;
	input->objective_id = 10;
	input->agent_id = 20;
	input->worker_id = 30;
	input->trace_id = 40;
	input->span_id = 50;
	input->parent_span_id = 60;
	input->generation = 70;
	input->action_id = 80;
	input->deadline_ns = 10000;
	input->backoff_base_ns = 100;
	input->max_attempts = 3;
	input->attempt = 1;
	input->failure_class = 2;
	input->severity = 3;
	input->flags = FRD_FLAG_TRACE_BOUND | FRD_FLAG_GENERATION_BOUND |
			FRD_FLAG_OBSERVATION | FRD_FLAG_DIAGNOSIS |
			FRD_FLAG_CHECKPOINT;
	fill_digest(input->observation_digest, 1);
	fill_digest(input->diagnosis_digest, 2);
	fill_digest(input->candidate_digest, 3);
	fill_digest(input->checkpoint_digest, 4);
}

int main(void)
{
	struct frd_service service;
	struct frd_policy policy = {
		.allowed_actions = FRD_ACTION_ALL,
		.max_attempts = 3,
		.require_operator_irreversible = 1,
		.require_compensation_irreversible = 1,
		.require_checkpoint_for_recovery = 1,
		.require_canary_for_candidate = 1,
		.max_backoff_ns = 5000,
	};
	struct frd_input input;
	struct frd_decision decision;
	struct frd_decision fetched;

	if (frd_init(&service, &policy) != FRD_OK)
		return fail("init", FRD_ERR_ARGUMENT);
	base_input(&input, 1);
	input.requested_action = FRD_ACTION_RETRY;
	input.flags |= FRD_FLAG_IDEMPOTENT;
	if (frd_decide(&service, &input, &decision) != FRD_OK ||
	    decision.action != FRD_ACTION_RETRY || decision.next_attempt_ns != 200)
		return fail("retry decision", FRD_ERR_POLICY);
	printf("M231_RETRY_DECISION_OK next=%llu\n",
	       (unsigned long long)decision.next_attempt_ns);
	if (frd_verify(&service, &input, &decision, 70) != FRD_OK)
		return fail("retry receipt", FRD_ERR_CORRUPT);
	printf("M231_RECEIPT_VERIFY_OK\n");

	decision.receipt_digest[0] ^= 1;
	if (frd_verify(&service, &input, &decision, 70) != FRD_ERR_CORRUPT)
		return fail("receipt tamper", FRD_ERR_CORRUPT);
	printf("M231_RECEIPT_TAMPER_REJECT_OK\n");
	if (frd_get(&service, 1, &fetched) != FRD_OK)
		return fail("decision query", FRD_ERR_NOT_FOUND);
	printf("M231_DECISION_QUERY_OK\n");

	base_input(&input, 2);
	input.requested_action = FRD_ACTION_REROUTE | FRD_ACTION_REPLAN;
	input.attempt = 2;
	input.flags |= FRD_FLAG_CANDIDATE | FRD_FLAG_CANARY_PASSED;
	if (frd_decide(&service, &input, &decision) != FRD_OK ||
	    decision.action != (FRD_ACTION_REROUTE | FRD_ACTION_REPLAN) ||
	    decision.next_attempt_ns != 300)
		return fail("reroute replan decision", FRD_ERR_POLICY);
	printf("M231_REROUTE_REPLAN_OK next=%llu\n",
	       (unsigned long long)decision.next_attempt_ns);

	base_input(&input, 3);
	input.requested_action = FRD_ACTION_ROLLBACK;
	input.flags |= FRD_FLAG_CANDIDATE | FRD_FLAG_CANARY_PASSED |
			FRD_FLAG_MODEL_PROPOSAL;
	if (frd_decide(&service, &input, &decision) != FRD_ERR_AUTHORITY)
		return fail("model rollback authority", FRD_ERR_AUTHORITY);
	printf("M231_MODEL_ROLLBACK_AUTHORITY_REJECT_OK\n");
	input.flags |= FRD_FLAG_AUTHORITY | FRD_FLAG_COMPENSATION;
	if (frd_decide(&service, &input, &decision) != FRD_OK ||
	    decision.action != FRD_ACTION_ROLLBACK)
		return fail("authorized rollback", FRD_ERR_POLICY);
	printf("M231_AUTHORIZED_ROLLBACK_OK\n");

	base_input(&input, 2);
	input.requested_action = FRD_ACTION_RETRY;
	input.flags |= FRD_FLAG_IDEMPOTENT;
	if (frd_decide(&service, &input, &decision) != FRD_ERR_REPLAY)
		return fail("request replay", FRD_ERR_REPLAY);
	printf("M231_REQUEST_REPLAY_REJECT_OK\n");

	base_input(&input, 4);
	input.requested_action = FRD_ACTION_RETRY;
	input.flags |= FRD_FLAG_IDEMPOTENT;
	input.attempt = 3;
	input.backoff_base_ns = 1000;
	input.deadline_ns = 1000;
	if (frd_decide(&service, &input, &decision) != FRD_ERR_DEADLINE)
		return fail("backoff deadline", FRD_ERR_DEADLINE);
	printf("M231_BACKOFF_DEADLINE_REJECT_OK\n");

	base_input(&input, 5);
	input.requested_action = FRD_ACTION_RETRY;
	input.flags = FRD_FLAG_TRACE_BOUND | FRD_FLAG_GENERATION_BOUND |
			      FRD_FLAG_OBSERVATION | FRD_FLAG_DIAGNOSIS;
	if (frd_decide(&service, &input, &decision) != FRD_ERR_POLICY)
		return fail("missing retry evidence", FRD_ERR_POLICY);
	printf("M231_MISSING_EVIDENCE_REJECT_OK\n");

	base_input(&input, 6);
	input.requested_action = FRD_ACTION_RETRY;
	input.flags |= FRD_FLAG_IDEMPOTENT;
	if (frd_decide(&service, &input, &decision) != FRD_OK)
		return fail("generation source decision", FRD_ERR_POLICY);
	if (frd_verify(&service, &input, &decision, 71) != FRD_ERR_STALE)
		return fail("generation stale", FRD_ERR_STALE);
	printf("M231_GENERATION_FENCE_OK\n");

	printf("M231_SELFTEST_EXIT=0\n");
	return 0;
}
