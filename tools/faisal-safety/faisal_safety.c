#include "faisal_safety.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[FSA_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0U;
	int result = FSA_ERR_TAMPER;

	if ((data == NULL && length != 0U) || digest == NULL)
		return FSA_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return FSA_ERR_IO;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, data, length) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) == 1 &&
	    digest_length == FSA_DIGEST_SIZE)
		result = FSA_OK;
	EVP_MD_CTX_free(ctx);
	return result;
}

static int digest_present(const uint8_t digest[FSA_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 0;
	for (i = 0U; i < FSA_DIGEST_SIZE; ++i)
		if (digest[i] != 0U)
			return 1;
	return 0;
}

static int bounded_string(const char *value, size_t size)
{
	return value != NULL && value[0] != '\0' && memchr(value, '\0', size) != NULL;
}

static int write_full(int fd, const void *data, size_t length)
{
	const uint8_t *bytes = data;
	size_t written = 0U;
	ssize_t count;

	while (written < length) {
		count = write(fd, bytes + written, length - written);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return FSA_ERR_IO;
		written += (size_t)count;
	}
	return FSA_OK;
}

static int read_full(int fd, void *data, size_t length)
{
	uint8_t *bytes = data;
	size_t read_bytes = 0U;
	ssize_t count;

	while (read_bytes < length) {
		count = read(fd, bytes + read_bytes, length - read_bytes);
		if (count < 0 && errno == EINTR)
			continue;
		if (count == 0)
			return read_bytes == 0U ? FSA_ERR_NOT_FOUND : FSA_ERR_CORRUPT;
		if (count < 0)
			return FSA_ERR_IO;
		read_bytes += (size_t)count;
	}
	return FSA_OK;
}

static int digest_event(const struct fsa_event *event, const uint8_t *payload,
			 size_t payload_len, uint8_t digest[FSA_DIGEST_SIZE])
{
	struct fsa_event canonical;
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0U;
	int result = FSA_ERR_TAMPER;

	if (event == NULL || (payload == NULL && payload_len != 0U) || digest == NULL)
		return FSA_ERR_ARGUMENT;
	canonical = *event;
	memset(canonical.event_digest, 0, sizeof(canonical.event_digest));
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return FSA_ERR_IO;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, &canonical, sizeof(canonical)) == 1 &&
	    EVP_DigestUpdate(ctx, payload, payload_len) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) == 1 &&
	    digest_length == FSA_DIGEST_SIZE)
		result = FSA_OK;
	EVP_MD_CTX_free(ctx);
	return result;
}

static int incident_index(const struct fsa_service *service, uint64_t incident_id)
{
	size_t i;

	for (i = 0U; i < service->incident_count; ++i)
		if (service->incidents[i].incident_id == incident_id)
			return (int)i;
	return -1;
}

static int token_index(const struct fsa_service *service, uint64_t token_id)
{
	size_t i;

	for (i = 0U; i < service->token_count; ++i)
		if (service->tokens[i].token_id == token_id)
			return (int)i;
	return -1;
}

static int valid_policy(const struct fsa_policy *policy)
{
	if (policy == NULL || policy->abi_version != FSA_ABI_VERSION ||
	    (policy->flags & ~(FSA_FLAG_FAIL_CLOSED | FSA_FLAG_REQUIRE_IDENTITY |
			       FSA_FLAG_REQUIRE_CAPABILITY | FSA_FLAG_REQUIRE_RESOURCE |
			       FSA_FLAG_REQUIRE_PROVENANCE | FSA_FLAG_REQUIRE_ATTESTATION |
			       FSA_FLAG_REQUIRE_CHECKPOINT_HIGH_RISK |
			       FSA_FLAG_REQUIRE_OPERATOR_HIGH_RISK)) != 0U ||
	    policy->max_risk_ppm > 1000000U || policy->max_anomaly_ppm > 1000000U ||
	    policy->max_decision_age_ns == 0U || policy->max_token_ttl_ns == 0U ||
	    policy->generation == 0U || !digest_present(policy->policy_digest) ||
	    !bounded_string(policy->name, sizeof(policy->name)))
		return FSA_ERR_ARGUMENT;
	return FSA_OK;
}

static int valid_request(const struct fsa_service *service,
			const struct fsa_request *request)
{
	if (service == NULL || request == NULL || request->abi_version != FSA_ABI_VERSION ||
	    request->workload_id == 0U || request->tenant_id == 0U ||
	    request->agent_id == 0U || request->generation == 0U ||
	    request->policy_generation != service->policy.generation ||
	    request->submitted_at_ns == 0U ||
	    request->deadline_ns < request->submitted_at_ns ||
	    request->risk_ppm > 1000000U || request->anomaly_ppm > 1000000U ||
	    request->attestation_state > FSA_ATTESTATION_UNAVAILABLE ||
	    (request->granted_capabilities & ~request->requested_capabilities) != 0U)
		return FSA_ERR_POLICY;
	return FSA_OK;
}

static int append_record_locked(struct fsa_service *service, uint16_t kind,
				uint64_t target_id, uint64_t generation,
				uint64_t observed_at_ns, int32_t status,
				const void *payload, size_t payload_len)
{
	struct fsa_disk_record record;
	int result;

	if (service == NULL || (payload == NULL && payload_len != 0U) ||
	    payload_len > FSA_MAX_PAYLOAD)
		return FSA_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.event.magic = FSA_EVENT_MAGIC;
	record.event.version = FSA_EVENT_VERSION;
	record.event.kind = kind;
	record.event.sequence = service->next_sequence;
	record.event.target_id = target_id;
	record.event.generation = generation;
	record.event.observed_at_ns = observed_at_ns;
	record.event.status = status;
	record.event.payload_len = (uint32_t)payload_len;
	memcpy(record.event.previous_digest, service->chain_digest,
	       FSA_DIGEST_SIZE);
	if (payload_len != 0U)
		memcpy(record.payload, payload, payload_len);
	if (digest_bytes(record.payload, payload_len,
			 record.event.payload_digest) != FSA_OK ||
	    digest_event(&record.event, record.payload, payload_len,
			 record.event.event_digest) != FSA_OK)
		return FSA_ERR_TAMPER;
	result = write_full(service->journal_fd, &record, sizeof(record));
	if (result != FSA_OK || fdatasync(service->journal_fd) != 0)
		return FSA_ERR_IO;
	service->next_sequence++;
	memcpy(service->chain_digest, record.event.event_digest, FSA_DIGEST_SIZE);
	return FSA_OK;
}

static int replace_incident(struct fsa_service *service,
			    const struct fsa_incident *incident)
{
	int index = incident_index(service, incident->incident_id);

	if (index < 0) {
		if (service->incident_count >= FSA_MAX_INCIDENTS)
			return FSA_ERR_FULL;
		service->incidents[service->incident_count++] = *incident;
	} else {
		service->incidents[index] = *incident;
	}
	if (incident->incident_id >= service->next_incident_id)
		service->next_incident_id = incident->incident_id + 1U;
	return FSA_OK;
}

static int replace_token(struct fsa_service *service,
			 const struct fsa_containment_token *token)
{
	int index = token_index(service, token->token_id);

	if (index < 0) {
		if (service->token_count >= FSA_MAX_TOKENS)
			return FSA_ERR_FULL;
		service->tokens[service->token_count++] = *token;
	} else {
		service->tokens[index] = *token;
	}
	if (token->token_id >= service->next_token_id)
		service->next_token_id = token->token_id + 1U;
	return FSA_OK;
}

static int apply_record(struct fsa_service *service,
			const struct fsa_disk_record *record)
{
	struct fsa_decision decision;
	struct fsa_incident incident;
	struct fsa_containment_token token;

	if (record->event.payload_len > FSA_MAX_PAYLOAD)
		return FSA_ERR_CORRUPT;
	switch (record->event.kind) {
	case FSA_EVENT_DECISION:
		if (record->event.payload_len != sizeof(decision))
			return FSA_ERR_CORRUPT;
		memcpy(&decision, record->payload, sizeof(decision));
		if (decision.decision_id != record->event.target_id ||
		    decision.policy_generation != service->policy.generation)
			return FSA_ERR_CORRUPT;
		service->decisions++;
		if (decision.decision_id >= service->next_decision_id)
			service->next_decision_id = decision.decision_id + 1U;
		if (decision.action == FSA_ACTION_QUARANTINE)
			service->quarantines++;
		if (decision.action == FSA_ACTION_TERMINATE)
			service->terminations++;
		return FSA_OK;
	case FSA_EVENT_INCIDENT_START:
	case FSA_EVENT_INCIDENT_TRANSITION:
		if (record->event.payload_len != sizeof(incident))
			return FSA_ERR_CORRUPT;
		memcpy(&incident, record->payload, sizeof(incident));
		if (incident.incident_id != record->event.target_id ||
		    incident.generation != record->event.generation)
			return FSA_ERR_CORRUPT;
		return replace_incident(service, &incident);
	case FSA_EVENT_CONTAINMENT_TOKEN:
		if (record->event.payload_len != sizeof(token))
			return FSA_ERR_CORRUPT;
		memcpy(&token, record->payload, sizeof(token));
		if (token.token_id != record->event.target_id ||
		    token.generation != record->event.generation)
			return FSA_ERR_CORRUPT;
		return replace_token(service, &token);
	default:
		return FSA_ERR_CORRUPT;
	}
}

static void reset_state(struct fsa_service *service)
{
	service->incident_count = 0U;
	service->token_count = 0U;
	service->next_decision_id = 1U;
	service->next_incident_id = 1U;
	service->next_token_id = 1U;
	service->decisions = 0U;
	service->quarantines = 0U;
	service->terminations = 0U;
	service->next_sequence = 1U;
	memset(service->incidents, 0, sizeof(service->incidents));
	memset(service->tokens, 0, sizeof(service->tokens));
	memset(service->chain_digest, 0, sizeof(service->chain_digest));
}

static int replay_locked(struct fsa_service *service)
{
	struct fsa_disk_record record;
	uint8_t previous[FSA_DIGEST_SIZE] = {0};
	uint8_t payload_digest[FSA_DIGEST_SIZE];
	uint8_t event_digest[FSA_DIGEST_SIZE];
	int result;

	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FSA_ERR_IO;
	while ((result = read_full(service->journal_fd, &record, sizeof(record))) == FSA_OK) {
		if (record.event.payload_len > FSA_MAX_PAYLOAD ||
		    record.event.magic != FSA_EVENT_MAGIC ||
		    record.event.version != FSA_EVENT_VERSION ||
		    record.event.sequence != service->next_sequence ||
		    memcmp(record.event.previous_digest, previous, FSA_DIGEST_SIZE) != 0 ||
		    digest_bytes(record.payload, record.event.payload_len,
				 payload_digest) != FSA_OK ||
		    memcmp(payload_digest, record.event.payload_digest,
			   FSA_DIGEST_SIZE) != 0 ||
		    digest_event(&record.event, record.payload, record.event.payload_len,
				 event_digest) != FSA_OK ||
		    memcmp(event_digest, record.event.event_digest,
			   FSA_DIGEST_SIZE) != 0 || apply_record(service, &record) != FSA_OK)
			return FSA_ERR_REPLAY;
		service->next_sequence++;
		memcpy(previous, record.event.event_digest, FSA_DIGEST_SIZE);
		memcpy(service->chain_digest, previous, FSA_DIGEST_SIZE);
	}
	if (result != FSA_ERR_NOT_FOUND)
		return result;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FSA_ERR_IO;
	return FSA_OK;
}

int fsa_open(struct fsa_service *service, const char *journal_path,
	     const struct fsa_policy *policy)
{
	int result;

	if (service == NULL || journal_path == NULL || valid_policy(policy) != FSA_OK)
		return FSA_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy = *policy;
	service->journal_fd = open(journal_path, O_CREAT | O_RDWR | O_APPEND, 0600);
	if (service->journal_fd < 0)
		return FSA_ERR_IO;
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->journal_fd);
		return FSA_ERR_IO;
	}
	reset_state(service);
	result = replay_locked(service);
	if (result != FSA_OK) {
		pthread_mutex_destroy(&service->lock);
		close(service->journal_fd);
		service->journal_fd = -1;
	}
	return result;
}

void fsa_close(struct fsa_service *service)
{
	if (service == NULL)
		return;
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	if (service->journal_fd >= 0)
		pthread_mutex_destroy(&service->lock);
	service->journal_fd = -1;
}

int fsa_replay(struct fsa_service *service)
{
	int result;

	if (service == NULL || service->journal_fd < 0)
		return FSA_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FSA_ERR_IO;
	reset_state(service);
	result = replay_locked(service);
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fsa_advance_time(struct fsa_service *service, uint64_t now_ns)
{
	if (service == NULL || now_ns < service->policy.current_time_ns)
		return FSA_ERR_STALE;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FSA_ERR_IO;
	service->policy.current_time_ns = now_ns;
	pthread_mutex_unlock(&service->lock);
	return FSA_OK;
}

int fsa_query_attestation(const struct fsa_service *service,
			  struct fsa_attestation *out)
{
	if (service == NULL || out == NULL)
		return FSA_ERR_ARGUMENT;
	if (pthread_mutex_lock((pthread_mutex_t *)&service->lock) != 0)
		return FSA_ERR_IO;
	memset(out, 0, sizeof(*out));
	out->last_sequence = service->next_sequence - 1U;
	out->next_decision_id = service->next_decision_id;
	out->next_incident_id = service->next_incident_id;
	out->next_token_id = service->next_token_id;
	out->decisions = service->decisions;
	out->incidents = service->incident_count;
	out->quarantines = service->quarantines;
	out->terminations = service->terminations;
	memcpy(out->chain_digest, service->chain_digest, FSA_DIGEST_SIZE);
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return FSA_OK;
}

static void append_reason(char *reason, size_t size, const char *text)
{
	if (reason[0] != '\0')
		snprintf(reason + strlen(reason), size - strlen(reason), ";%s", text);
	else
		snprintf(reason, size, "%s", text);
}

static int compute_decision_digest(struct fsa_decision *decision)
{
	struct fsa_decision canonical = *decision;

	memset(canonical.decision_digest, 0, sizeof(canonical.decision_digest));
	return digest_bytes(&canonical, sizeof(canonical), decision->decision_digest);
}

int fsa_evaluate(struct fsa_service *service, const struct fsa_request *request,
		struct fsa_decision *out)
{
	struct fsa_decision decision;
	uint32_t violations = 0U;
	uint64_t restricted = 0U;
	int result;

	if (service == NULL || request == NULL || out == NULL)
		return FSA_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FSA_ERR_IO;
	result = valid_request(service, request);
	if (result != FSA_OK) {
		pthread_mutex_unlock(&service->lock);
		return result;
	}
	memset(&decision, 0, sizeof(decision));
	decision.decision_id = service->next_decision_id;
	decision.workload_id = request->workload_id;
	decision.agent_id = request->agent_id;
	decision.policy_generation = service->policy.generation;
	decision.observed_at_ns = service->policy.current_time_ns;
	decision.expiry_ns = service->policy.current_time_ns + service->policy.max_decision_age_ns;
	if (digest_bytes(request, sizeof(*request), decision.request_digest) != FSA_OK) {
		pthread_mutex_unlock(&service->lock);
		return FSA_ERR_TAMPER;
	}
	if (request->model_claimed_authority) {
		violations |= FSA_VIOLATION_MODEL_AUTHORITY;
		decision.action = FSA_ACTION_TERMINATE;
		append_reason(decision.reason, sizeof(decision.reason), "model_output_is_not_authority");
	}
	if ((service->policy.flags & FSA_FLAG_REQUIRE_IDENTITY) &&
	    !digest_present(request->identity_digest)) {
		violations |= FSA_VIOLATION_IDENTITY;
		append_reason(decision.reason, sizeof(decision.reason), "identity_missing");
	}
	if ((service->policy.flags & FSA_FLAG_REQUIRE_CAPABILITY) &&
	    request->requested_capabilities == 0U) {
		violations |= FSA_VIOLATION_CAPABILITY;
		append_reason(decision.reason, sizeof(decision.reason), "capability_missing");
	}
	if ((request->granted_capabilities & ~request->requested_capabilities) != 0U) {
		violations |= FSA_VIOLATION_CAPABILITY;
		append_reason(decision.reason, sizeof(decision.reason), "capability_escalation");
	}
	if ((service->policy.flags & FSA_FLAG_REQUIRE_RESOURCE) &&
	    (request->cpu_budget_ns == 0U || request->memory_limit_bytes == 0U ||
	     request->network_limit_bytes == 0U || request->storage_limit_bytes == 0U)) {
		violations |= FSA_VIOLATION_RESOURCE;
		append_reason(decision.reason, sizeof(decision.reason), "resource_budget_missing");
	}
	if ((service->policy.flags & FSA_FLAG_REQUIRE_PROVENANCE) &&
	    (!request->provenance_verified || !digest_present(request->provenance_digest) ||
	     !request->artifact_verified || !digest_present(request->artifact_digest))) {
		violations |= FSA_VIOLATION_PROVENANCE;
		append_reason(decision.reason, sizeof(decision.reason), "provenance_or_artifact_unverified");
	}
	if ((service->policy.flags & FSA_FLAG_REQUIRE_ATTESTATION) &&
	    (request->attestation_state != FSA_ATTESTATION_TRUSTED ||
	     !digest_present(request->attestation_digest))) {
		violations |= FSA_VIOLATION_ATTESTATION;
		append_reason(decision.reason, sizeof(decision.reason), "attestation_untrusted");
	}
	if (request->risk_ppm > service->policy.max_risk_ppm) {
		violations |= FSA_VIOLATION_RISK;
		append_reason(decision.reason, sizeof(decision.reason), "risk_threshold_exceeded");
	}
	if (request->anomaly_ppm > service->policy.max_anomaly_ppm) {
		violations |= FSA_VIOLATION_ANOMALY;
		append_reason(decision.reason, sizeof(decision.reason), "anomaly_threshold_exceeded");
	}
	if (request->deadline_ns <= service->policy.current_time_ns) {
		violations |= FSA_VIOLATION_DEADLINE;
		append_reason(decision.reason, sizeof(decision.reason), "deadline_expired");
	}
	if ((service->policy.flags & FSA_FLAG_REQUIRE_CHECKPOINT_HIGH_RISK) &&
	    (request->requested_capabilities & FSA_HIGH_RISK_CAPS) != 0U &&
	    !request->checkpoint_available) {
		violations |= FSA_VIOLATION_CHECKPOINT;
		append_reason(decision.reason, sizeof(decision.reason), "checkpoint_required");
	}
	if ((service->policy.flags & FSA_FLAG_REQUIRE_OPERATOR_HIGH_RISK) &&
	    (request->requested_capabilities & FSA_HIGH_RISK_CAPS) != 0U &&
	    !request->operator_approved) {
		violations |= FSA_VIOLATION_OPERATOR;
		decision.requires_operator = 1U;
		append_reason(decision.reason, sizeof(decision.reason), "operator_review_required");
	}
	if ((violations & FSA_VIOLATION_MODEL_AUTHORITY) != 0U ||
	    (violations & FSA_VIOLATION_DEADLINE) != 0U) {
		decision.action = FSA_ACTION_TERMINATE;
	} else if ((violations & (FSA_VIOLATION_IDENTITY | FSA_VIOLATION_PROVENANCE |
				 FSA_VIOLATION_ATTESTATION | FSA_VIOLATION_ANOMALY |
				 FSA_VIOLATION_RISK)) != 0U) {
		decision.action = FSA_ACTION_QUARANTINE;
	} else if ((violations & FSA_VIOLATION_OPERATOR) != 0U) {
		decision.action = FSA_ACTION_OPERATOR_REVIEW;
	} else if ((violations & FSA_VIOLATION_CHECKPOINT) != 0U) {
		decision.action = FSA_ACTION_CHECKPOINT;
	} else if (violations != 0U) {
		decision.action = FSA_ACTION_RESTRICT;
	}
	if (decision.action == 0U) {
		decision.action = FSA_ACTION_ALLOW;
		append_reason(decision.reason, sizeof(decision.reason), "policy_allow");
	}
	if (decision.action == FSA_ACTION_RESTRICT ||
	    decision.action == FSA_ACTION_QUARANTINE ||
	    decision.action == FSA_ACTION_TERMINATE ||
	    decision.action == FSA_ACTION_CHECKPOINT ||
	    decision.action == FSA_ACTION_OPERATOR_REVIEW)
		restricted = request->requested_capabilities;
	decision.restricted_capabilities = restricted;
	decision.violation_mask = violations;
	if (compute_decision_digest(&decision) != FSA_OK) {
		pthread_mutex_unlock(&service->lock);
		return FSA_ERR_TAMPER;
	}
	result = append_record_locked(service, FSA_EVENT_DECISION,
				      decision.decision_id, request->generation,
				      decision.observed_at_ns, decision.action,
				      &decision, sizeof(decision));
	if (result == FSA_OK) {
		service->next_decision_id++;
		service->decisions++;
		if (decision.action == FSA_ACTION_QUARANTINE)
			service->quarantines++;
		if (decision.action == FSA_ACTION_TERMINATE)
			service->terminations++;
		*out = decision;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

static int transition_allowed(uint32_t old_state, uint32_t next_state)
{
	switch (old_state) {
	case FSA_INCIDENT_DETECTED:
		return next_state == FSA_INCIDENT_TRIAGED || next_state == FSA_INCIDENT_CONTAINED ||
		       next_state == FSA_INCIDENT_ESCALATED || next_state == FSA_INCIDENT_TERMINATED;
	case FSA_INCIDENT_TRIAGED:
		return next_state == FSA_INCIDENT_CONTAINED || next_state == FSA_INCIDENT_ESCALATED ||
		       next_state == FSA_INCIDENT_TERMINATED;
	case FSA_INCIDENT_CONTAINED:
		return next_state == FSA_INCIDENT_RECOVERING || next_state == FSA_INCIDENT_ESCALATED ||
		       next_state == FSA_INCIDENT_TERMINATED;
	case FSA_INCIDENT_RECOVERING:
		return next_state == FSA_INCIDENT_RECOVERED || next_state == FSA_INCIDENT_ESCALATED ||
		       next_state == FSA_INCIDENT_TERMINATED;
	case FSA_INCIDENT_RECOVERED:
		return next_state == FSA_INCIDENT_CLOSED || next_state == FSA_INCIDENT_ESCALATED;
	case FSA_INCIDENT_ESCALATED:
		return next_state == FSA_INCIDENT_CONTAINED || next_state == FSA_INCIDENT_RECOVERING ||
		       next_state == FSA_INCIDENT_TERMINATED;
	case FSA_INCIDENT_TERMINATED:
		return next_state == FSA_INCIDENT_CLOSED;
	default:
		return 0;
	}
}

int fsa_open_incident(struct fsa_service *service, uint64_t workload_id,
		      uint64_t agent_id, uint64_t generation, uint64_t now_ns,
		      uint32_t severity, uint32_t action, uint32_t violation_mask,
		      const char *reason, struct fsa_incident *out)
{
	struct fsa_incident incident;
	int result;

	if (service == NULL || workload_id == 0U || agent_id == 0U || generation == 0U ||
	    now_ns == 0U || severity == 0U || action < FSA_ACTION_RESTRICT ||
	    action > FSA_ACTION_OPERATOR_REVIEW || violation_mask == 0U ||
	    reason == NULL || memchr(reason, '\0', FSA_MAX_REASON) == NULL || out == NULL)
		return FSA_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FSA_ERR_IO;
	if (service->incident_count >= FSA_MAX_INCIDENTS) {
		pthread_mutex_unlock(&service->lock);
		return FSA_ERR_FULL;
	}
	memset(&incident, 0, sizeof(incident));
	incident.incident_id = service->next_incident_id;
	incident.workload_id = workload_id;
	incident.agent_id = agent_id;
	incident.generation = generation;
	incident.opened_at_ns = now_ns;
	incident.updated_at_ns = now_ns;
	incident.state = FSA_INCIDENT_DETECTED;
	incident.action = action;
	incident.severity = severity;
	incident.violation_mask = violation_mask;
	snprintf(incident.reason, sizeof(incident.reason), "%s", reason);
	if (digest_bytes(&incident, sizeof(incident), incident.evidence_digest) != FSA_OK) {
		pthread_mutex_unlock(&service->lock);
		return FSA_ERR_TAMPER;
	}
	result = append_record_locked(service, FSA_EVENT_INCIDENT_START,
				      incident.incident_id, generation, now_ns,
				      action, &incident, sizeof(incident));
	if (result == FSA_OK) {
		service->next_incident_id++;
		service->incidents[service->incident_count++] = incident;
		*out = incident;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fsa_transition_incident(struct fsa_service *service, uint64_t incident_id,
			    uint64_t generation, uint64_t now_ns, uint32_t next_state,
			    uint64_t checkpoint_id,
			    const uint8_t evidence_digest[FSA_DIGEST_SIZE],
			    const char *reason, struct fsa_incident *out)
{
	struct fsa_incident incident;
	int index;
	int result;

	if (service == NULL || incident_id == 0U || generation == 0U || now_ns == 0U ||
	    next_state < FSA_INCIDENT_DETECTED || next_state > FSA_INCIDENT_TERMINATED ||
	    !digest_present(evidence_digest) || reason == NULL ||
	    memchr(reason, '\0', FSA_MAX_REASON) == NULL || out == NULL)
		return FSA_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FSA_ERR_IO;
	index = incident_index(service, incident_id);
	if (index < 0) {
		pthread_mutex_unlock(&service->lock);
		return FSA_ERR_NOT_FOUND;
	}
	incident = service->incidents[index];
	if (incident.generation != generation || now_ns < incident.updated_at_ns) {
		pthread_mutex_unlock(&service->lock);
		return FSA_ERR_GENERATION;
	}
	if (!transition_allowed(incident.state, next_state) ||
	    ((next_state == FSA_INCIDENT_RECOVERING || next_state == FSA_INCIDENT_RECOVERED) &&
	     checkpoint_id == 0U)) {
		pthread_mutex_unlock(&service->lock);
		return FSA_ERR_STATE;
	}
	incident.state = next_state;
	incident.updated_at_ns = now_ns;
	incident.checkpoint_id = checkpoint_id;
	incident.transition_count++;
	memcpy(incident.evidence_digest, evidence_digest, FSA_DIGEST_SIZE);
	snprintf(incident.reason, sizeof(incident.reason), "%s", reason);
	result = append_record_locked(service, FSA_EVENT_INCIDENT_TRANSITION,
				      incident_id, generation, now_ns,
				      next_state, &incident, sizeof(incident));
	if (result == FSA_OK) {
		service->incidents[index] = incident;
		*out = incident;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fsa_issue_containment(struct fsa_service *service, uint64_t workload_id,
			  uint64_t agent_id, uint64_t generation, uint64_t now_ns,
			  uint64_t ttl_ns, uint32_t action,
			  uint64_t restricted_capabilities,
			  struct fsa_containment_token *out)
{
	struct fsa_containment_token token;
	int result;

	if (service == NULL || workload_id == 0U || agent_id == 0U || generation == 0U ||
	    now_ns == 0U || ttl_ns == 0U || ttl_ns > service->policy.max_token_ttl_ns ||
	    action < FSA_ACTION_RESTRICT || action > FSA_ACTION_TERMINATE ||
	    restricted_capabilities == 0U || out == NULL)
		return FSA_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FSA_ERR_IO;
	if (service->token_count >= FSA_MAX_TOKENS) {
		pthread_mutex_unlock(&service->lock);
		return FSA_ERR_FULL;
	}
	memset(&token, 0, sizeof(token));
	token.token_id = service->next_token_id;
	token.workload_id = workload_id;
	token.agent_id = agent_id;
	token.generation = generation;
	token.issued_at_ns = now_ns;
	token.expires_at_ns = now_ns + ttl_ns;
	token.action = action;
	token.restricted_capabilities = restricted_capabilities;
	if (digest_bytes(&token, sizeof(token), token.token_digest) != FSA_OK) {
		pthread_mutex_unlock(&service->lock);
		return FSA_ERR_TAMPER;
	}
	result = append_record_locked(service, FSA_EVENT_CONTAINMENT_TOKEN,
				      token.token_id, generation, now_ns,
				      action, &token, sizeof(token));
	if (result == FSA_OK) {
		service->next_token_id++;
		service->tokens[service->token_count++] = token;
		*out = token;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fsa_verify_containment(const struct fsa_service *service,
			   const struct fsa_containment_token *token,
			   uint64_t now_ns, uint64_t workload_id, uint64_t agent_id,
			   uint64_t generation)
{
	struct fsa_containment_token canonical;
	uint8_t digest[FSA_DIGEST_SIZE];
	int index;

	if (service == NULL || token == NULL || now_ns == 0U ||
	    workload_id == 0U || agent_id == 0U || generation == 0U)
		return FSA_ERR_ARGUMENT;
	canonical = *token;
	memset(canonical.token_digest, 0, sizeof(canonical.token_digest));
	if (digest_bytes(&canonical, sizeof(canonical), digest) != FSA_OK ||
	    memcmp(digest, token->token_digest, FSA_DIGEST_SIZE) != 0 ||
	    token->expires_at_ns < now_ns || token->workload_id != workload_id ||
	    token->agent_id != agent_id || token->generation != generation)
		return FSA_ERR_CONTAINMENT;
	if (pthread_mutex_lock((pthread_mutex_t *)&service->lock) != 0)
		return FSA_ERR_IO;
	index = token_index(service, token->token_id);
	if (index < 0 || memcmp(&service->tokens[index], token, sizeof(*token)) != 0)
		index = -1;
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return index < 0 ? FSA_ERR_CONTAINMENT : FSA_OK;
}

int fsa_query_incident(const struct fsa_service *service, uint64_t incident_id,
			   struct fsa_incident *out)
{
	int index;

	if (service == NULL || incident_id == 0U || out == NULL)
		return FSA_ERR_ARGUMENT;
	if (pthread_mutex_lock((pthread_mutex_t *)&service->lock) != 0)
		return FSA_ERR_IO;
	index = incident_index(service, incident_id);
	if (index < 0) {
		pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
		return FSA_ERR_NOT_FOUND;
	}
	*out = service->incidents[index];
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return FSA_OK;
}

int fsa_test_model_authority_denial(struct fsa_service *service,
				    const struct fsa_request *request)
{
	struct fsa_request proposal;
	struct fsa_decision decision;
	int result;

	if (service == NULL || request == NULL)
		return FSA_ERR_ARGUMENT;
	proposal = *request;
	proposal.model_claimed_authority = 1U;
	result = fsa_evaluate(service, &proposal, &decision);
	return result == FSA_OK && decision.action == FSA_ACTION_TERMINATE &&
		(decision.violation_mask & FSA_VIOLATION_MODEL_AUTHORITY) != 0U ?
		FSA_OK : FSA_ERR_AUTHORITY;
}

int fsa_test_invalid_incident_transition(struct fsa_service *service,
					 uint64_t incident_id)
{
	struct fsa_incident incident;
	uint8_t evidence[FSA_DIGEST_SIZE];
	int result;

	if (service == NULL || fsa_query_incident(service, incident_id, &incident) != FSA_OK)
		return FSA_ERR_ARGUMENT;
	memset(evidence, 0xA5, sizeof(evidence));
	result = fsa_transition_incident(service, incident_id, incident.generation,
					 incident.updated_at_ns + 1U,
					 FSA_INCIDENT_CLOSED, 0U, evidence,
					 "invalid-transition", &incident);
	return result == FSA_ERR_STATE ? FSA_OK : FSA_ERR_STATE;
}

int fsa_test_corrupt_tail(const struct fsa_service *service)
{
	uint8_t byte = 0xA5U;

	if (service == NULL || service->journal_fd < 0)
		return FSA_ERR_ARGUMENT;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0 ||
	    write_full(service->journal_fd, &byte, sizeof(byte)) != FSA_OK ||
	    fdatasync(service->journal_fd) != 0)
		return FSA_ERR_IO;
	return FSA_OK;
}
