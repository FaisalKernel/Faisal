#include "../../faisal-trace-correlation/faisal_trace_correlation.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *name, int rc)
{
	fprintf(stderr, "M234_FAIL:%s rc=%d\n", name, rc);
	return 1;
}

static void fill_bytes(uint8_t *bytes, size_t length, uint8_t value)
{
	size_t i;

	for (i = 0; i < length; i++)
		bytes[i] = value;
}

static void make_context(struct mtc_context *context)
{
	memset(context, 0, sizeof(*context));
	fill_bytes(context->trace_id, sizeof(context->trace_id), 0x11);
	fill_bytes(context->span_id, sizeof(context->span_id), 0x22);
	context->trace_flags = 1;
}

static void make_event(struct mtc_event *event, uint64_t sequence,
		       uint32_t kind, uint32_t flags, uint64_t generation,
		       uint64_t observed_at)
{
	memset(event, 0, sizeof(*event));
	event->event_sequence = sequence;
	event->generation = generation;
	event->observed_at_ns = observed_at;
	event->kind = kind;
	event->flags = flags;
	event->context.trace_id[0] = 0x11;
	event->context.span_id[0] = (uint8_t)(0x20 + sequence);
	event->lineage.agent_id = 41;
	event->lineage.objective_id = 42;
	event->lineage.task_id = 43;
	event->attribute[0] = 'e';
	event->attribute[1] = 'v';
	event->attribute[2] = (char)('0' + (sequence % 10));
}

int main(void)
{
	const struct mtc_policy policy = {
		.expected_generation = 9,
		.minimum_event_time_ns = 1000,
		.reject_external_context = 0,
		.reject_baggage = 1,
		.require_measured_external_events = 1,
		.max_events = 16,
	};
	struct mtc_service service;
	struct mtc_context root;
	struct mtc_event event1;
	struct mtc_event event2;
	struct mtc_event event3;
	struct mtc_event output;
	struct mtc_event queried;

	make_context(&root);
	if (mtc_init(&service, &policy, &root, 9) != MTC_OK)
		return fail("init", MTC_ERR_ARGUMENT);
	if (mtc_validate_context(&root) != MTC_OK)
		return fail("context", MTC_ERR_CONTEXT);
	printf("M234_CONTEXT_VALIDATION_OK\n");

	make_event(&event1, 1, MTC_KIND_OBJECTIVE, MTC_FLAG_MEASURED, 9, 1000);
	if (mtc_record_event(&service, &event1, &event1) != MTC_OK)
		return fail("objective event", MTC_ERR_ARGUMENT);
	if (mtc_verify_event(&service, &event1) != MTC_OK)
		return fail("objective verify", MTC_ERR_CORRUPT);
	printf("M234_OBJECTIVE_EVENT_OK\n");

	make_event(&event2, 2, MTC_KIND_MODEL_REQUEST,
		   MTC_FLAG_MEASURED | MTC_FLAG_MODEL_OUTPUT, 9, 1100);
	event2.provider_kind = 1;
	event2.lineage.model_request_id = 5001;
	event2.previous_event_sequence = event1.event_sequence;
	memcpy(event2.previous_event_digest, event1.digest,
	       MTC_DIGEST_SIZE);
	if (mtc_record_event(&service, &event2, &event2) != MTC_OK)
		return fail("model event", MTC_ERR_ARGUMENT);
	if (mtc_verify_event(&service, &event2) != MTC_OK)
		return fail("model verify", MTC_ERR_CORRUPT);
	printf("M234_MODEL_CORRELATION_OK\n");

	make_event(&event3, 3, MTC_KIND_TOOL_REQUEST,
		   MTC_FLAG_MEASURED | MTC_FLAG_TOOL_CALL, 9, 1200);
	event3.lineage.tool_request_id = 6001;
	event3.previous_event_sequence = event2.event_sequence;
	memcpy(event3.previous_event_digest, event2.digest,
	       MTC_DIGEST_SIZE);
	if (mtc_record_event(&service, &event3, &event3) != MTC_OK)
		return fail("tool event", MTC_ERR_ARGUMENT);
	printf("M234_TOOL_CORRELATION_OK\n");

	output = event2;
	output.digest[0] ^= 1;
	if (mtc_verify_event(&service, &output) != MTC_ERR_CORRUPT)
		return fail("tamper", MTC_ERR_CORRUPT);
	printf("M234_TAMPER_REJECT_OK\n");
	output = event3;
	output.event_sequence = 4;
	output.previous_event_digest[0] ^= 1;
	if (mtc_record_event(&service, &output, &queried) != MTC_ERR_CHAIN)
		return fail("chain tamper", MTC_ERR_CHAIN);
	printf("M234_CHAIN_TAMPER_REJECT_OK\n");
	if (mtc_record_event(&service, &event3, &queried) != MTC_ERR_REPLAY)
		return fail("replay", MTC_ERR_REPLAY);
	printf("M234_REPLAY_REJECT_OK\n");

	make_event(&output, 4, MTC_KIND_COMPLETION, MTC_FLAG_MEASURED, 10, 1300);
	output.previous_event_sequence = event3.event_sequence;
	memcpy(output.previous_event_digest, event3.digest, MTC_DIGEST_SIZE);
	if (mtc_record_event(&service, &output, &queried) != MTC_ERR_GENERATION)
		return fail("generation", MTC_ERR_GENERATION);
	printf("M234_GENERATION_REJECT_OK\n");

	make_event(&output, 4, MTC_KIND_MODEL_REQUEST,
		   MTC_FLAG_EXTERNAL_CONTEXT | MTC_FLAG_MODEL_OUTPUT, 9, 1300);
	output.provider_kind = 2;
	output.lineage.model_request_id = 5002;
	output.previous_event_sequence = event3.event_sequence;
	memcpy(output.previous_event_digest, event3.digest, MTC_DIGEST_SIZE);
	if (mtc_record_event(&service, &output, &queried) != MTC_ERR_CONTEXT)
		return fail("unmeasured external", MTC_ERR_CONTEXT);
	printf("M234_UNMEASURED_EXTERNAL_REJECT_OK\n");

	make_event(&output, 4, MTC_KIND_WORLD_OBSERVATION,
		   MTC_FLAG_MEASURED | MTC_FLAG_BAGGAGE_ALLOWED, 9, 1300);
	output.previous_event_sequence = event3.event_sequence;
	memcpy(output.previous_event_digest, event3.digest, MTC_DIGEST_SIZE);
	if (mtc_record_event(&service, &output, &queried) != MTC_ERR_CONTEXT)
		return fail("baggage", MTC_ERR_CONTEXT);
	printf("M234_BAGGAGE_REJECT_OK\n");

	if (mtc_query_event(&service, 2, &queried) != MTC_OK ||
	    queried.lineage.model_request_id != 5001)
		return fail("query", MTC_ERR_NOT_FOUND);
	printf("M234_QUERY_OK\n");
	if (mtc_authority_check(&event2) != MTC_ERR_AUTHORITY)
		return fail("authority", MTC_ERR_AUTHORITY);
	printf("M234_MODEL_NONAUTHORITY_OK\n");
	printf("M234_SELFTEST_EXIT=0\n");
	return 0;
}
