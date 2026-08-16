#define _GNU_SOURCE
#include "faisal_collaboration_service.h"
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct fcl_record_header {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint32_t size;
	uint64_t sequence;
};

enum fcl_record_kind {
	FCL_RECORD_AGENT = 1,
	FCL_RECORD_CAPABILITY = 2,
	FCL_RECORD_TEAM = 3,
	FCL_RECORD_MESSAGE = 4,
	FCL_RECORD_VOTE = 5
};

static void digest_text(const char *text, uint8_t digest[FCL_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int length = 0;
	if (!ctx || !EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
	    !EVP_DigestUpdate(ctx, text, strlen(text)) ||
	    !EVP_DigestFinal_ex(ctx, digest, &length) ||
	    length != FCL_DIGEST_SIZE)
		memset(digest, 0, FCL_DIGEST_SIZE);
	EVP_MD_CTX_free(ctx);
}

static int record(struct fcl_service *service, uint16_t kind,
		  const void *payload, uint32_t size)
{
	struct fcl_record_header header = {
		.magic = FCL_JOURNAL_MAGIC,
		.version = FCL_JOURNAL_VERSION,
		.kind = kind,
		.size = size,
		.sequence = service->next_sequence++
	};
	if (write(service->journal_fd, &header, sizeof(header)) != sizeof(header) ||
	    write(service->journal_fd, payload, size) != (ssize_t)size ||
	    fsync(service->journal_fd) < 0)
		return FCL_ERR_IO;
	return FCL_OK;
}

static struct fcl_agent *agent(struct fcl_service *s, uint64_t id)
{
	size_t i;
	for (i = 0; i < s->agent_count; i++)
		if (s->agents[i].agent_id == id)
			return &s->agents[i];
	return NULL;
}

static struct fcl_capability *capability(struct fcl_service *s, uint64_t id)
{
	size_t i;
	for (i = 0; i < s->capability_count; i++)
		if (s->capabilities[i].capability_id == id)
			return &s->capabilities[i];
	return NULL;
}

static struct fcl_team *team(struct fcl_service *s, uint64_t id)
{
	size_t i;
	for (i = 0; i < s->team_count; i++)
		if (s->teams[i].team_id == id)
			return &s->teams[i];
	return NULL;
}

static struct fcl_vote *vote_record(struct fcl_service *s, uint64_t id)
{
	size_t i;
	for (i = 0; i < s->vote_count; i++)
		if (s->votes[i].vote_id == id)
			return &s->votes[i];
	return NULL;
}

static int member(const struct fcl_team *team_item, uint64_t agent_id)
{
	uint32_t i;
	for (i = 0; i < team_item->member_count; i++)
		if (team_item->members[i] == agent_id)
			return 1;
	return 0;
}

int fcl_replay(struct fcl_service *service)
{
	struct fcl_record_header header;
	uint8_t payload[sizeof(struct fcl_agent) > sizeof(struct fcl_message) ?
			 sizeof(struct fcl_agent) : sizeof(struct fcl_message)];
	if (!service || service->journal_fd < 0 || lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FCL_ERR_ARGUMENT;
	service->agent_count = service->capability_count = service->team_count = 0;
	service->message_count = service->vote_count = 0;
	service->next_sequence = 1;
	for (;;) {
		ssize_t got = read(service->journal_fd, &header, sizeof(header));
		if (got == 0)
			break;
		if (got != sizeof(header) || header.magic != FCL_JOURNAL_MAGIC ||
		    header.version != FCL_JOURNAL_VERSION || header.size > sizeof(payload) ||
		    read(service->journal_fd, payload, header.size) != (ssize_t)header.size)
			return FCL_ERR_CORRUPT;
		if (header.kind == FCL_RECORD_AGENT && header.size == sizeof(struct fcl_agent)) {
			struct fcl_agent *item = (struct fcl_agent *)payload;
			struct fcl_agent *old = agent(service, item->agent_id);
			if (old) *old = *item;
			else if (service->agent_count < FCL_MAX_AGENTS) service->agents[service->agent_count++] = *item;
			else return FCL_ERR_FULL;
		} else if (header.kind == FCL_RECORD_CAPABILITY && header.size == sizeof(struct fcl_capability)) {
			struct fcl_capability *item = (struct fcl_capability *)payload;
			struct fcl_capability *old = capability(service, item->capability_id);
			if (old) *old = *item;
			else if (service->capability_count < FCL_MAX_CAPABILITIES) service->capabilities[service->capability_count++] = *item;
			else return FCL_ERR_FULL;
		} else if (header.kind == FCL_RECORD_TEAM && header.size == sizeof(struct fcl_team)) {
			struct fcl_team *item = (struct fcl_team *)payload;
			struct fcl_team *old = team(service, item->team_id);
			if (old) *old = *item;
			else if (service->team_count < FCL_MAX_TEAMS) service->teams[service->team_count++] = *item;
			else return FCL_ERR_FULL;
		} else if (header.kind == FCL_RECORD_MESSAGE && header.size == sizeof(struct fcl_message)) {
			if (service->message_count >= FCL_MAX_MESSAGES) return FCL_ERR_FULL;
			service->messages[service->message_count++] = *(struct fcl_message *)payload;
		} else if (header.kind == FCL_RECORD_VOTE && header.size == sizeof(struct fcl_vote)) {
			struct fcl_vote *item = (struct fcl_vote *)payload;
			struct fcl_vote *old = vote_record(service, item->vote_id);
			if (old) *old = *item;
			else if (service->vote_count < FCL_MAX_VOTES) service->votes[service->vote_count++] = *item;
			else return FCL_ERR_FULL;
		} else {
			return FCL_ERR_CORRUPT;
		}
		service->next_sequence = header.sequence + 1;
	}
	return lseek(service->journal_fd, 0, SEEK_END) < 0 ? FCL_ERR_IO : FCL_OK;
}

int fcl_open(struct fcl_service *service, const char *journal_path)
{
	int rc;
	if (!service || !journal_path || strlen(journal_path) >= sizeof(service->journal_path))
		return FCL_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	strncpy(service->journal_path, journal_path, sizeof(service->journal_path) - 1);
	service->journal_fd = open(journal_path, O_RDWR | O_CREAT | O_APPEND, 0600);
	if (service->journal_fd < 0)
		return FCL_ERR_IO;
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->journal_fd);
		return FCL_ERR_IO;
	}
	service->lock_initialized = 1;
	service->next_agent_id = service->next_capability_id = service->next_team_id = 1;
	service->next_message_id = service->next_vote_id = 1;
	rc = fcl_replay(service);
	if (rc != FCL_OK) fcl_close(service);
	return rc;
}

void fcl_close(struct fcl_service *service)
{
	if (!service) return;
	if (service->lock_initialized) pthread_mutex_destroy(&service->lock);
	service->lock_initialized = 0;
	if (service->journal_fd >= 0) close(service->journal_fd);
	service->journal_fd = -1;
}

int fcl_register_agent(struct fcl_service *service, const char *name,
			       uint64_t parent_agent_id, uint64_t now_ns,
			       struct fcl_agent *out)
{
	struct fcl_agent item;
	if (!service || !name || !*name || !out || strlen(name) >= sizeof(item.name)) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	if (service->agent_count >= FCL_MAX_AGENTS || (parent_agent_id && !agent(service, parent_agent_id))) {
		pthread_mutex_unlock(&service->lock); return parent_agent_id ? FCL_ERR_NOT_FOUND : FCL_ERR_FULL;
	}
	memset(&item, 0, sizeof(item));
	item.agent_id = service->next_agent_id++;
	item.parent_agent_id = parent_agent_id;
	item.identity_capability = item.agent_id ^ 0xa5a55a5a5a5aa5a5ULL;
	item.generation = 1;
	item.last_heartbeat_ns = now_ns;
	item.state = FCL_AGENT_AVAILABLE;
	item.trust_ppm = 500000;
	strncpy(item.name, name, sizeof(item.name) - 1);
	service->agents[service->agent_count++] = item;
	if (record(service, FCL_RECORD_AGENT, &item, sizeof(item)) != FCL_OK) {
		service->agent_count--; pthread_mutex_unlock(&service->lock); return FCL_ERR_IO;
	}
	*out = item;
	pthread_mutex_unlock(&service->lock);
	return FCL_OK;
}

int fcl_heartbeat(struct fcl_service *service, uint64_t agent_id, uint64_t now_ns)
{
	struct fcl_agent *item;
	if (!service) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	item = agent(service, agent_id);
	if (!item) { pthread_mutex_unlock(&service->lock); return FCL_ERR_NOT_FOUND; }
	item->last_heartbeat_ns = now_ns;
	item->state = FCL_AGENT_AVAILABLE;
	record(service, FCL_RECORD_AGENT, item, sizeof(*item));
	pthread_mutex_unlock(&service->lock);
	return FCL_OK;
}

int fcl_register_capability(struct fcl_service *service, uint64_t agent_id,
				   const char *name, const char *description,
				   uint64_t resource_mask, struct fcl_capability *out)
{
	struct fcl_capability item;
	struct fcl_agent *owner;
	if (!service || !name || !description || !*name || !out ||
	    strlen(name) >= sizeof(item.name) || strlen(description) >= sizeof(item.description)) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	owner = agent(service, agent_id);
	if (!owner || service->capability_count >= FCL_MAX_CAPABILITIES) { pthread_mutex_unlock(&service->lock); return FCL_ERR_NOT_FOUND; }
	memset(&item, 0, sizeof(item));
	item.capability_id = service->next_capability_id++;
	item.provider_agent_id = agent_id;
	item.generation = 1;
	item.resource_mask = resource_mask;
	item.state = FCL_AGENT_AVAILABLE;
	strncpy(item.name, name, sizeof(item.name) - 1);
	strncpy(item.description, description, sizeof(item.description) - 1);
	service->capabilities[service->capability_count++] = item;
	owner->capability_count++;
	if (record(service, FCL_RECORD_CAPABILITY, &item, sizeof(item)) != FCL_OK) { pthread_mutex_unlock(&service->lock); return FCL_ERR_IO; }
	record(service, FCL_RECORD_AGENT, owner, sizeof(*owner));
	*out = item;
	pthread_mutex_unlock(&service->lock);
	return FCL_OK;
}

int fcl_find_capability(const struct fcl_service *service, const char *name,
				       struct fcl_capability *out)
{
	struct fcl_service *s = (struct fcl_service *)service;
	size_t i;
	if (!service || !name || !out) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&s->lock);
	for (i = 0; i < s->capability_count; i++) if (!strcmp(s->capabilities[i].name, name)) { *out = s->capabilities[i]; pthread_mutex_unlock(&s->lock); return FCL_OK; }
	pthread_mutex_unlock(&s->lock);
	return FCL_ERR_NOT_FOUND;
}

int fcl_create_team(struct fcl_service *service, uint64_t owner_agent_id,
			   uint64_t objective_id, uint32_t persistent,
			   uint32_t quorum_required, struct fcl_team *out)
{
	struct fcl_team item;
	if (!service || !out || !owner_agent_id || !quorum_required) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	if (!agent(service, owner_agent_id) || service->team_count >= FCL_MAX_TEAMS) { pthread_mutex_unlock(&service->lock); return FCL_ERR_NOT_FOUND; }
	memset(&item, 0, sizeof(item));
	item.team_id = service->next_team_id++;
	item.owner_agent_id = owner_agent_id;
	item.objective_id = objective_id;
	item.generation = 1;
	item.persistent = persistent != 0;
	item.quorum_required = quorum_required;
	item.member_count = 1;
	item.members[0] = owner_agent_id;
	item.state = FCL_AGENT_AVAILABLE;
	service->teams[service->team_count++] = item;
	if (record(service, FCL_RECORD_TEAM, &item, sizeof(item)) != FCL_OK) { service->team_count--; pthread_mutex_unlock(&service->lock); return FCL_ERR_IO; }
	*out = item;
	pthread_mutex_unlock(&service->lock);
	return FCL_OK;
}

int fcl_join_team(struct fcl_service *service, uint64_t team_id, uint64_t agent_id)
{
	struct fcl_team *item;
	if (!service) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	item = team(service, team_id);
	if (!item || !agent(service, agent_id)) { pthread_mutex_unlock(&service->lock); return FCL_ERR_NOT_FOUND; }
	if (member(item, agent_id)) { pthread_mutex_unlock(&service->lock); return FCL_OK; }
	if (item->member_count >= FCL_MAX_TEAM_MEMBERS) { pthread_mutex_unlock(&service->lock); return FCL_ERR_FULL; }
	item->members[item->member_count++] = agent_id;
	record(service, FCL_RECORD_TEAM, item, sizeof(*item));
	pthread_mutex_unlock(&service->lock);
	return FCL_OK;
}

static int send_locked(struct fcl_service *service, uint64_t team_id,
			       uint64_t sender, uint64_t target, uint32_t kind,
			       uint32_t schema, const char *payload, uint64_t correlation,
			       struct fcl_message *out)
{
	struct fcl_team *group = team(service, team_id);
	struct fcl_message item;
	if (!group || !member(group, sender) || (target && !member(group, target))) return FCL_ERR_AUTHORITY;
	if (!payload || !*payload || strlen(payload) >= sizeof(item.payload)) return FCL_ERR_ARGUMENT;
	if (service->message_count >= FCL_MAX_MESSAGES) return FCL_ERR_FULL;
	memset(&item, 0, sizeof(item));
	item.message_id = service->next_message_id++;
	item.team_id = team_id;
	item.sender_agent_id = sender;
	item.target_agent_id = target;
	item.correlation = correlation;
	item.sequence = service->next_sequence;
	item.kind = kind;
	item.schema = schema;
	strncpy(item.payload, payload, sizeof(item.payload) - 1);
	digest_text(payload, item.payload_digest);
	service->messages[service->message_count++] = item;
	if (record(service, FCL_RECORD_MESSAGE, &item, sizeof(item)) != FCL_OK) return FCL_ERR_IO;
	if (out) *out = item;
	return FCL_OK;
}

int fcl_send(struct fcl_service *service, uint64_t team_id, uint64_t sender_agent_id,
		    uint64_t target_agent_id, uint32_t kind, uint32_t schema,
		    const char *payload, uint64_t correlation, struct fcl_message *out)
{
	int rc;
	if (!service) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	rc = send_locked(service, team_id, sender_agent_id, target_agent_id, kind, schema, payload, correlation, out);
	pthread_mutex_unlock(&service->lock);
	return rc;
}

int fcl_request_evidence(struct fcl_service *service, uint64_t team_id,
				 uint64_t sender_agent_id, uint64_t target_agent_id,
				 const char *request, struct fcl_message *out)
{
	return fcl_send(service, team_id, sender_agent_id, target_agent_id, FCL_MSG_EVIDENCE_REQUEST, 1, request, 0, out);
}

int fcl_challenge(struct fcl_service *service, uint64_t team_id, uint64_t sender_agent_id,
			 uint64_t target_agent_id, const uint8_t subject_digest[FCL_DIGEST_SIZE],
			 const char *reason, struct fcl_message *out)
{
	char payload[FCL_MAX_TEXT];
	unsigned int i;
	if (!subject_digest || !reason) return FCL_ERR_ARGUMENT;
	snprintf(payload, sizeof(payload), "challenge:%s:digest=", reason);
	for (i = 0; i < 4; i++) snprintf(payload + strlen(payload), sizeof(payload) - strlen(payload), "%02x", subject_digest[i]);
	return fcl_send(service, team_id, sender_agent_id, target_agent_id, FCL_MSG_CHALLENGE, 1, payload, 0, out);
}

int fcl_open_vote(struct fcl_service *service, uint64_t team_id, uint64_t subject_sequence,
			 const uint8_t subject_digest[FCL_DIGEST_SIZE], struct fcl_vote *out)
{
	struct fcl_team *group;
	struct fcl_vote item;
	if (!service || !subject_digest || !out) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	group = team(service, team_id);
	if (!group || group->member_count < group->quorum_required || service->vote_count >= FCL_MAX_VOTES) { pthread_mutex_unlock(&service->lock); return FCL_ERR_QUORUM; }
	memset(&item, 0, sizeof(item));
	item.vote_id = service->next_vote_id++;
	item.team_id = team_id;
	item.subject_sequence = subject_sequence;
	item.quorum_required = group->quorum_required;
	item.state = FCL_VOTE_OPEN;
	memcpy(item.subject_digest, subject_digest, FCL_DIGEST_SIZE);
	service->votes[service->vote_count++] = item;
	if (record(service, FCL_RECORD_VOTE, &item, sizeof(item)) != FCL_OK) { service->vote_count--; pthread_mutex_unlock(&service->lock); return FCL_ERR_IO; }
	*out = item;
	pthread_mutex_unlock(&service->lock);
	return FCL_OK;
}

int fcl_vote(struct fcl_service *service, uint64_t vote_id, uint64_t agent_id,
		    int approve, struct fcl_vote *out)
{
	struct fcl_vote *item;
	struct fcl_team *group;
	(void)agent_id;
	if (!service || !out) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	item = vote_record(service, vote_id);
	group = item ? team(service, item->team_id) : NULL;
	if (!item || !group || !member(group, agent_id) || item->state != FCL_VOTE_OPEN) { pthread_mutex_unlock(&service->lock); return FCL_ERR_AUTHORITY; }
	if (approve) item->approvals++; else item->rejections++;
	if (item->approvals >= item->quorum_required) item->state = FCL_VOTE_PASSED;
	else if (item->rejections > group->member_count - item->quorum_required) item->state = FCL_VOTE_REJECTED;
	record(service, FCL_RECORD_VOTE, item, sizeof(*item));
	*out = *item;
	pthread_mutex_unlock(&service->lock);
	return FCL_OK;
}

int fcl_escalate(struct fcl_service *service, uint64_t team_id, uint64_t sender_agent_id,
			 const char *reason, struct fcl_message *out)
{
	return fcl_send(service, team_id, sender_agent_id, 0, FCL_MSG_ESCALATION, 1, reason, 0, out);
}

int fcl_recover_agent(struct fcl_service *service, uint64_t agent_id, uint64_t now_ns,
			      uint32_t *redistributed, struct fcl_agent *out)
{
	struct fcl_agent *item;
	size_t i;
	if (!service || !redistributed || !out) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	item = agent(service, agent_id);
	if (!item) { pthread_mutex_unlock(&service->lock); return FCL_ERR_NOT_FOUND; }
	item->state = FCL_AGENT_RECOVERING;
	item->generation++;
	item->last_heartbeat_ns = now_ns;
	*redistributed = 0;
	for (i = 0; i < service->message_count; i++)
		if (service->messages[i].target_agent_id == agent_id && service->messages[i].kind == FCL_MSG_DELEGATE)
			(*redistributed)++;
	item->state = FCL_AGENT_AVAILABLE;
	record(service, FCL_RECORD_AGENT, item, sizeof(*item));
	*out = *item;
	pthread_mutex_unlock(&service->lock);
	return FCL_OK;
}

int fcl_query_agent(const struct fcl_service *service, uint64_t agent_id, struct fcl_agent *out)
{
	struct fcl_service *s = (struct fcl_service *)service;
	struct fcl_agent *item;
	if (!service || !out) return FCL_ERR_ARGUMENT;
	pthread_mutex_lock(&s->lock);
	item = agent(s, agent_id);
	if (!item) { pthread_mutex_unlock(&s->lock); return FCL_ERR_NOT_FOUND; }
	*out = *item;
	pthread_mutex_unlock(&s->lock);
	return FCL_OK;
}
