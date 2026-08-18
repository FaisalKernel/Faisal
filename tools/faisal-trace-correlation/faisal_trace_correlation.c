#include "faisal_trace_correlation.h"

#include <openssl/evp.h>
#include <string.h>

static int bytes_nonzero(const uint8_t *bytes, size_t length)
{
	size_t i;

	if (!bytes)
		return 0;
	for (i = 0; i < length; i++)
		if (bytes[i] != 0)
			return 1;
	return 0;
}

static void digest_update(EVP_MD_CTX *ctx, const void *data, size_t length)
{
	(void)EVP_DigestUpdate(ctx, data, length);
}

static int digest_event(const struct mtc_event *event,
			uint8_t digest[MTC_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int length = 0;

	if (!event || !digest)
		return MTC_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return MTC_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		return MTC_ERR_CORRUPT;
	}
	digest_update(ctx, &event->event_sequence, sizeof(event->event_sequence));
	digest_update(ctx, &event->generation, sizeof(event->generation));
	digest_update(ctx, &event->observed_at_ns, sizeof(event->observed_at_ns));
	digest_update(ctx, &event->kind, sizeof(event->kind));
	digest_update(ctx, &event->flags, sizeof(event->flags));
	digest_update(ctx, &event->provider_kind, sizeof(event->provider_kind));
	digest_update(ctx, &event->capability_kind, sizeof(event->capability_kind));
	digest_update(ctx, &event->context, sizeof(event->context));
	digest_update(ctx, &event->lineage, sizeof(event->lineage));
	digest_update(ctx, &event->provider_sequence, sizeof(event->provider_sequence));
	digest_update(ctx, &event->cursor, sizeof(event->cursor));
	digest_update(ctx, event->provider_digest, sizeof(event->provider_digest));
	digest_update(ctx, &event->previous_event_sequence,
		     sizeof(event->previous_event_sequence));
	digest_update(ctx, event->previous_event_digest,
		     sizeof(event->previous_event_digest));
	digest_update(ctx, event->attribute, sizeof(event->attribute));
	if (EVP_DigestFinal_ex(ctx, digest, &length) != 1 ||
	    length != MTC_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return MTC_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return MTC_OK;
}

int mtc_validate_context(const struct mtc_context *context)
{
	if (!context || !bytes_nonzero(context->trace_id, sizeof(context->trace_id)) ||
	    !bytes_nonzero(context->span_id, sizeof(context->span_id)))
		return MTC_ERR_CONTEXT;
	if (bytes_nonzero(context->span_id, sizeof(context->span_id)) &&
	    !memcmp(context->span_id, context->parent_span_id,
		    sizeof(context->span_id)))
		return MTC_ERR_CONTEXT;
	return MTC_OK;
}

int mtc_init(struct mtc_service *service, const struct mtc_policy *policy,
		 const struct mtc_context *root_context,
		 uint64_t trace_generation)
{
	if (!service || !policy || !root_context || !trace_generation ||
	    policy->max_events == 0 || policy->max_events > MTC_MAX_EVENTS ||
	    mtc_validate_context(root_context) != MTC_OK)
		return MTC_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy = *policy;
	service->trace_generation = trace_generation;
	return MTC_OK;
}

static int policy_accepts(const struct mtc_service *service,
			 const struct mtc_event *event)
{
	if (event->generation != service->trace_generation ||
	    event->observed_at_ns < service->policy.minimum_event_time_ns)
		return MTC_ERR_GENERATION;
	if (mtc_validate_context(&event->context) != MTC_OK)
		return MTC_ERR_CONTEXT;
	if (service->policy.reject_external_context &&
	    (event->flags & MTC_FLAG_EXTERNAL_CONTEXT))
		return MTC_ERR_CONTEXT;
	if (service->policy.reject_baggage &&
	    (event->flags & MTC_FLAG_BAGGAGE_ALLOWED))
		return MTC_ERR_CONTEXT;
	if (service->policy.require_measured_external_events &&
	    (event->flags & (MTC_FLAG_EXTERNAL_CONTEXT | MTC_FLAG_MODEL_OUTPUT)) &&
	    !(event->flags & MTC_FLAG_MEASURED))
		return MTC_ERR_CONTEXT;
	if (event->kind == 0 || event->event_sequence == 0)
		return MTC_ERR_ARGUMENT;
	if ((event->flags & MTC_FLAG_MODEL_OUTPUT) &&
	    !(event->lineage.model_request_id || event->provider_kind))
		return MTC_ERR_ARGUMENT;
	return MTC_OK;
}

int mtc_record_event(struct mtc_service *service, const struct mtc_event *event,
		     struct mtc_event *out)
{
	struct mtc_event copy;
	uint8_t digest[MTC_DIGEST_SIZE];
	int rc;

	if (!service || !event || !out || service->event_count >= service->policy.max_events)
		return MTC_ERR_FULL;
	rc = policy_accepts(service, event);
	if (rc != MTC_OK)
		return rc;
	if (event->event_sequence <= service->last_event_sequence)
		return MTC_ERR_REPLAY;
	if (service->event_count == 0) {
		if (event->previous_event_sequence != 0 ||
		    bytes_nonzero(event->previous_event_digest,
				   sizeof(event->previous_event_digest)))
			return MTC_ERR_CHAIN;
	} else {
		if (event->previous_event_sequence != service->last_event_sequence ||
		    memcmp(event->previous_event_digest, service->last_event_digest,
			   MTC_DIGEST_SIZE) != 0)
			return MTC_ERR_CHAIN;
	}
	copy = *event;
	memset(copy.digest, 0, sizeof(copy.digest));
	if (digest_event(&copy, digest) != MTC_OK)
		return MTC_ERR_CORRUPT;
	memcpy(copy.digest, digest, sizeof(copy.digest));
	service->events[service->event_count++] = copy;
	service->last_event_sequence = copy.event_sequence;
	memcpy(service->last_event_digest, copy.digest,
	       sizeof(service->last_event_digest));
	*out = copy;
	return MTC_OK;
}

int mtc_verify_event(const struct mtc_service *service,
		     const struct mtc_event *event)
{
	struct mtc_event copy;
	uint8_t digest[MTC_DIGEST_SIZE];
	int rc;

	if (!service || !event)
		return MTC_ERR_ARGUMENT;
	rc = policy_accepts(service, event);
	if (rc != MTC_OK)
		return rc;
	copy = *event;
	memset(copy.digest, 0, sizeof(copy.digest));
	if (digest_event(&copy, digest) != MTC_OK ||
	    memcmp(digest, event->digest, MTC_DIGEST_SIZE) != 0)
		return MTC_ERR_CORRUPT;
	if (event->event_sequence > 1 &&
	    (!event->previous_event_sequence ||
	     !bytes_nonzero(event->previous_event_digest,
			    sizeof(event->previous_event_digest))))
		return MTC_ERR_CHAIN;
	return MTC_OK;
}

int mtc_query_event(const struct mtc_service *service, uint64_t event_sequence,
		   struct mtc_event *out)
{
	size_t i;

	if (!service || !out || !event_sequence)
		return MTC_ERR_ARGUMENT;
	for (i = 0; i < service->event_count; i++)
		if (service->events[i].event_sequence == event_sequence) {
			*out = service->events[i];
			return MTC_OK;
		}
	return MTC_ERR_NOT_FOUND;
}

int mtc_authority_check(const struct mtc_event *event)
{
	if (!event)
		return MTC_ERR_ARGUMENT;
	return MTC_ERR_AUTHORITY;
}
