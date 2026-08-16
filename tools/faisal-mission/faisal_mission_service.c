#define _GNU_SOURCE

#include "faisal_mission_service.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define M98_REASON_RECOVERY 1U
#define M98_REASON_POLICY 2U
#define M98_REASON_DEADLINE 3U
#define M98_REASON_BUDGET 4U
#define M98_REASON_STALE 5U
#define M98_REASON_VERIFICATION 6U
#define M98_REASON_AUTHORITY 7U
#define M98_MAX_STEPS 4096U

struct m98_disk_header {
	uint32_t magic;
	uint32_t version;
	uint32_t header_size;
	uint32_t record_size;
	uint64_t mission_sequence;
	uint64_t mission_id;
	uint8_t mission_digest[M98_DIGEST_SIZE];
};

static int write_all(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length) {
		ssize_t written = write(fd, cursor, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return M98_ERR_IO;
		}
		if (!written)
			return M98_ERR_IO;
		cursor += (size_t)written;
		length -= (size_t)written;
	}
	return M98_OK;
}

static int read_exact_or_eof(int fd, void *buffer, size_t length)
{
	unsigned char *cursor = buffer;
	size_t total = 0;

	while (total < length) {
		ssize_t received = read(fd, cursor + total, length - total);

		if (received < 0) {
			if (errno == EINTR)
				continue;
			return M98_ERR_IO;
		}
		if (!received)
			return total ? M98_ERR_CORRUPT : 1;
		total += (size_t)received;
	}
	return M98_OK;
}

static int digest_mission(const struct m98_mission *mission,
				  uint8_t digest[M98_DIGEST_SIZE])
{
	struct m98_mission canonical = *mission;
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	unsigned int output_length = 0;
	int result = M98_ERR_IO;

	if (!context)
		return M98_ERR_IO;
	memset(canonical.plan_digest, 0, sizeof(canonical.plan_digest));
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(context, &canonical, sizeof(canonical)) == 1 &&
	    EVP_DigestFinal_ex(context, digest, &output_length) == 1 &&
	    output_length == M98_DIGEST_SIZE)
		result = M98_OK;
	EVP_MD_CTX_free(context);
	return result;
}

static int digest_text(const char *text, uint8_t digest[M98_DIGEST_SIZE])
{
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	unsigned int output_length = 0;
	int result = M98_ERR_IO;

	if (!context || !text)
		goto out;
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(context, text, strlen(text)) == 1 &&
	    EVP_DigestFinal_ex(context, digest, &output_length) == 1 &&
	    output_length == M98_DIGEST_SIZE)
		result = M98_OK;
out:
	EVP_MD_CTX_free(context);
	return result;
}

static int nonzero_digest(const uint8_t digest[M98_DIGEST_SIZE])
{
	uint32_t index;

	for (index = 0; index < M98_DIGEST_SIZE; index++)
		if (digest[index])
			return 1;
	return 0;
}

static int copy_text(char *destination, size_t destination_size,
			     const char *source, int allow_empty)
{
	size_t length;

	if (!destination || !destination_size || !source)
		return M98_ERR_ARGUMENT;
	length = strnlen(source, destination_size);
	if ((!allow_empty && !length) || length >= destination_size)
		return M98_ERR_ARGUMENT;
	memcpy(destination, source, length + 1);
	return M98_OK;
}

static int lock_service(struct m98_service *service)
{
	if (!service || !service->lock_initialized)
		return M98_ERR_ARGUMENT;
	return pthread_mutex_lock(&service->lock) == 0 ? M98_OK : M98_ERR_STATE;
}

static void unlock_service(struct m98_service *service)
{
	(void)pthread_mutex_unlock(&service->lock);
}

static struct m98_mission *find_mission(struct m98_service *service,
					uint64_t mission_id)
{
	size_t index;

	for (index = 0; index < service->mission_count; index++)
		if (service->missions[index].mission_id == mission_id)
			return &service->missions[index];
	return NULL;
}

static int append_mission(struct m98_service *service,
				  const struct m98_mission *mission)
{
	struct m98_disk_header header;
	uint8_t digest[M98_DIGEST_SIZE];
	uint64_t sequence = service->mission_sequence + 1;
	int result;

	result = digest_mission(mission, digest);
	if (result != M98_OK)
		return result;
	memset(&header, 0, sizeof(header));
	header.magic = M98_MISSION_JOURNAL_MAGIC;
	header.version = M98_MISSION_JOURNAL_VERSION;
	header.header_size = sizeof(header);
	header.record_size = sizeof(header) + sizeof(*mission);
	header.mission_sequence = sequence;
	header.mission_id = mission->mission_id;
	memcpy(header.mission_digest, digest, sizeof(header.mission_digest));
	result = write_all(service->mission_fd, &header, sizeof(header));
	if (result == M98_OK)
		result = write_all(service->mission_fd, mission, sizeof(*mission));
	if (result == M98_OK && fdatasync(service->mission_fd) < 0)
		result = M98_ERR_IO;
	if (result == M98_OK)
		service->mission_sequence = sequence;
	return result;
}

static int apply_replayed(struct m98_service *service,
				 const struct m98_mission *mission)
{
	struct m98_mission *existing = find_mission(service, mission->mission_id);

	if (existing) {
		*existing = *mission;
		return M98_OK;
	}
	if (service->mission_count >= M98_MAX_MISSIONS)
		return M98_ERR_FULL;
	service->missions[service->mission_count++] = *mission;
	return M98_OK;
}

static int replay_unlocked(struct m98_service *service)
{
	struct m98_disk_header header;
	uint64_t last_sequence = 0;
	int result;

	if (lseek(service->mission_fd, 0, SEEK_SET) < 0)
		return M98_ERR_IO;
	service->mission_count = 0;
	service->mission_sequence = 0;
	service->next_mission_id = 1;
	for (;;) {
		struct m98_mission mission;
		uint8_t digest[M98_DIGEST_SIZE];

		result = read_exact_or_eof(service->mission_fd, &header,
					   sizeof(header));
		if (result == 1)
			break;
		if (result != M98_OK || header.magic != M98_MISSION_JOURNAL_MAGIC ||
		    header.version != M98_MISSION_JOURNAL_VERSION ||
		    header.header_size != sizeof(header) ||
		    header.record_size != sizeof(header) + sizeof(mission) ||
		    header.mission_sequence <= last_sequence || !header.mission_id)
			return M98_ERR_CORRUPT;
		result = read_exact_or_eof(service->mission_fd, &mission,
					   sizeof(mission));
		if (result != M98_OK || mission.mission_id != header.mission_id ||
		    mission.state < M98_MISSION_NEW ||
		    mission.state > M98_MISSION_ESCALATED ||
		    mission.trigger < M98_TRIGGER_MANUAL ||
		    mission.trigger > M98_TRIGGER_RECOVERY ||
		    (mission.decision && (mission.decision < M98_DECISION_CONTINUE ||
					  mission.decision > M98_DECISION_SUCCEED)) ||
		    !mission.max_steps || mission.max_steps > M98_MAX_STEPS ||
		    digest_mission(&mission, digest) != M98_OK ||
		    memcmp(digest, header.mission_digest, sizeof(digest)) != 0)
			return M98_ERR_CORRUPT;
		result = apply_replayed(service, &mission);
		if (result != M98_OK)
			return result;
		last_sequence = header.mission_sequence;
		if (mission.mission_id >= service->next_mission_id)
			service->next_mission_id = mission.mission_id + 1;
	}
	service->mission_sequence = last_sequence;
	return lseek(service->mission_fd, 0, SEEK_END) < 0 ? M98_ERR_IO : M98_OK;
}

static int mission_terminal(const struct m98_mission *mission)
{
	return mission->state == M98_MISSION_SUCCEEDED ||
	       mission->state == M98_MISSION_STOPPED ||
	       mission->state == M98_MISSION_ESCALATED;
}

static int mission_policy_check(const struct m98_mission *mission,
					 uint64_t now_ns)
{
	if (now_ns > mission->deadline_ns)
		return M98_ERR_DEADLINE;
	if (mission->consumed_cpu_ns > mission->cpu_budget_ns ||
	    mission->consumed_money_micro > mission->money_budget_micro)
		return M98_ERR_BUDGET;
	if (mission->step >= mission->max_steps)
		return M98_ERR_POLICY;
	if (mission->risk_class > mission->risk_ceiling)
		return M98_ERR_POLICY;
	return M98_OK;
}

static void set_terminal_reason(struct m98_mission *mission, int result)
{
	mission->state = result == M98_ERR_DEADLINE ? M98_MISSION_STOPPED :
		(result == M98_ERR_BUDGET ? M98_MISSION_STOPPED : M98_MISSION_ESCALATED);
	mission->stop_reason = result == M98_ERR_DEADLINE ? M98_REASON_DEADLINE :
		(result == M98_ERR_BUDGET ? M98_REASON_BUDGET : M98_REASON_POLICY);
	mission->escalation_reason = result == M98_ERR_POLICY ? M98_REASON_POLICY : 0;
	mission->decision = result == M98_ERR_DEADLINE || result == M98_ERR_BUDGET ?
		M98_DECISION_STOP : M98_DECISION_ESCALATE;
}

static int recover_inflight_unlocked(struct m98_service *service)
{
	size_t index;
	int result;

	for (index = 0; index < service->mission_count; index++) {
		struct m98_mission candidate = service->missions[index];

		if (candidate.state != M98_MISSION_EXECUTION_PENDING &&
		    candidate.state != M98_MISSION_EVIDENCE_PENDING)
			continue;
		candidate.state = M98_MISSION_ESCALATED;
		candidate.decision = M98_DECISION_ESCALATE;
		candidate.escalation_reason = M98_REASON_RECOVERY;
		candidate.updated_at_ns = candidate.updated_at_ns + 1;
		if (copy_text(candidate.reason, sizeof(candidate.reason),
			      "in-flight execution requires independent recovery review", 0) != M98_OK)
			return M98_ERR_ARGUMENT;
		result = append_mission(service, &candidate);
		if (result != M98_OK)
			return result;
		service->missions[index] = candidate;
	}
	return M98_OK;
}

int m98_open(struct m98_service *service, const char *journal_prefix,
		     int require_kernel)
{
	int result;

	if (!service || !journal_prefix || !*journal_prefix ||
	    strlen(journal_prefix) >= sizeof(service->mission_path))
		return M98_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->mission_fd = -1;
	result = fts_open(&service->tasks, journal_prefix, require_kernel);
	if (result != FTS_OK)
		return M98_ERR_IO;
	if (snprintf(service->mission_path, sizeof(service->mission_path),
		     "%s.mission", journal_prefix) < 0 ||
	    strlen(service->mission_path) >= sizeof(service->mission_path)) {
		fts_close(&service->tasks);
		return M98_ERR_ARGUMENT;
	}
	service->mission_fd = open(service->mission_path,
					 O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (service->mission_fd < 0) {
		fts_close(&service->tasks);
		return M98_ERR_IO;
	}
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->mission_fd);
		fts_close(&service->tasks);
		return M98_ERR_STATE;
	}
	service->lock_initialized = 1;
	result = replay_unlocked(service);
	if (result == M98_OK)
		result = recover_inflight_unlocked(service);
	if (result != M98_OK) {
		m98_close(service);
		return result;
	}
	return M98_OK;
}

void m98_close(struct m98_service *service)
{
	if (!service || !service->lock_initialized)
		return;
	(void)pthread_mutex_lock(&service->lock);
	if (service->mission_fd >= 0)
		close(service->mission_fd);
	service->mission_fd = -1;
	(void)pthread_mutex_unlock(&service->lock);
	pthread_mutex_destroy(&service->lock);
	service->lock_initialized = 0;
	fts_close(&service->tasks);
}

int m98_replay(struct m98_service *service)
{
	int result = lock_service(service);

	if (result != M98_OK)
		return result;
	result = replay_unlocked(service);
	if (result == M98_OK)
		result = recover_inflight_unlocked(service);
	unlock_service(service);
	return result;
}

int m98_create(struct m98_service *service, const char *objective,
		       const struct m98_policy *policy, uint64_t now_ns,
		       struct m98_mission *out)
{
	struct fts_task task;
	struct m98_mission mission;
	char idempotency[FTS_MAX_IDEMPOTENCY];
	int result;

	if (!service || !objective || !*objective || !policy || !out || !now_ns ||
	    policy->deadline_ns <= now_ns || !policy->cpu_budget_ns ||
	    !policy->money_budget_micro || !policy->max_steps ||
	    policy->max_steps > M98_MAX_STEPS || policy->max_retries > FTS_MAX_RETRIES ||
	    policy->risk_ceiling > 1000000U || !policy->supervisor_approved ||
	    !policy->operator_approved || !policy->supervisor_nonce ||
	    !policy->operator_nonce || policy->supervisor_nonce == policy->operator_nonce)
		return M98_ERR_ARGUMENT;
	if (strlen(objective) >= sizeof(mission.objective))
		return M98_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M98_OK)
		return result;
	if (service->mission_count >= M98_MAX_MISSIONS) {
		result = M98_ERR_FULL;
		goto out_unlock;
	}
	memset(&mission, 0, sizeof(mission));
	mission.mission_id = service->next_mission_id;
	if (snprintf(idempotency, sizeof(idempotency), "m98-mission-%llu",
		     (unsigned long long)mission.mission_id) < 0) {
		result = M98_ERR_ARGUMENT;
		goto out_unlock;
	}
	result = fts_submit(&service->tasks, mission.mission_id, idempotency,
			objective, policy->deadline_ns, policy->cpu_budget_ns,
			policy->money_budget_micro, 512, policy->risk_ceiling,
			policy->max_retries, NULL, 0, &task);
	if (result != FTS_OK)
		goto out_unlock;
	result = fts_claim(&service->tasks, task.task_id, now_ns,
			FTS_DEFAULT_LEASE_NS, &task);
	if (result != FTS_OK)
		goto out_unlock;
	mission.task_id = task.task_id;
	mission.created_at_ns = now_ns;
	mission.updated_at_ns = now_ns;
	mission.deadline_ns = policy->deadline_ns;
	mission.next_wakeup_ns = now_ns;
	mission.objective_generation = task.sequence;
	mission.state = M98_MISSION_ACTIVE;
	mission.trigger = M98_TRIGGER_MANUAL;
	mission.cpu_budget_ns = policy->cpu_budget_ns;
	mission.money_budget_micro = policy->money_budget_micro;
	mission.max_steps = policy->max_steps;
	mission.max_retries = policy->max_retries;
	mission.risk_ceiling = policy->risk_ceiling;
	mission.supervisor_nonce = policy->supervisor_nonce;
	mission.operator_nonce = policy->operator_nonce;
	result = copy_text(mission.objective, sizeof(mission.objective), objective, 0);
	if (result != M98_OK)
		goto out_unlock;
	result = append_mission(service, &mission);
	if (result == M98_OK) {
		service->missions[service->mission_count++] = mission;
		service->next_mission_id++;
		*out = mission;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m98_observe(struct m98_service *service, uint64_t mission_id,
		       uint64_t now_ns, uint64_t event_sequence,
		       uint32_t trigger, const uint8_t working_digest[M98_DIGEST_SIZE],
		       const uint8_t world_digest[M98_DIGEST_SIZE],
		       const uint8_t resource_digest[M98_DIGEST_SIZE],
		       const char *event, struct m98_mission *out)
{
	struct m98_mission *mission;
	struct m98_mission candidate;
	struct fts_continuity continuity;
	int result;

	if (!service || !mission_id || !now_ns || !event_sequence ||
	    event_sequence <= 0 || trigger < M98_TRIGGER_MANUAL ||
	    trigger > M98_TRIGGER_RECOVERY || !working_digest || !world_digest ||
	    !resource_digest || !nonzero_digest(working_digest) ||
	    !nonzero_digest(world_digest) || !nonzero_digest(resource_digest) ||
	    !event || !*event || strlen(event) >= M98_MAX_EVENT || !out)
		return M98_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M98_OK)
		return result;
	mission = find_mission(service, mission_id);
	if (!mission)
		result = M98_ERR_NOT_FOUND;
	else if (mission_terminal(mission))
		result = M98_ERR_STATE;
	else if (event_sequence <= mission->event_sequence)
		result = M98_ERR_STALE;
	else {
		result = mission_policy_check(mission, now_ns);
		if (result != M98_OK) {
			candidate = *mission;
			set_terminal_reason(&candidate, result);
			candidate.updated_at_ns = now_ns;
			(void)copy_text(candidate.reason, sizeof(candidate.reason),
					"mission policy stop during observation", 0);
			if (append_mission(service, &candidate) == M98_OK) {
				*mission = candidate;
				*out = candidate;
			}
			goto out_unlock;
		}
		if (mission->capsule_id) {
			result = fts_continuity_check(&service->tasks, mission->capsule_id,
						      working_digest, world_digest,
						      resource_digest, &continuity);
			if (result != FTS_OK) {
				int exposed_result = result == FTS_ERR_STALE ? M98_ERR_STALE :
					(result == FTS_ERR_REVOKED ? M98_ERR_ESCALATED : M98_ERR_IO);

				candidate = *mission;
				candidate.state = result == FTS_ERR_REVOKED ?
					M98_MISSION_ESCALATED : M98_MISSION_REPLAN_REQUIRED;
				candidate.decision = result == FTS_ERR_REVOKED ?
					M98_DECISION_ESCALATE : M98_DECISION_REPLAN;
				candidate.escalation_reason = result == FTS_ERR_REVOKED ?
					M98_REASON_AUTHORITY : M98_REASON_STALE;
				candidate.updated_at_ns = now_ns;
				(void)copy_text(candidate.reason, sizeof(candidate.reason),
						"continuity mismatch requires fresh observation and replan", 0);
				if (append_mission(service, &candidate) == M98_OK) {
					*mission = candidate;
					*out = candidate;
				}
				result = exposed_result;
				goto out_unlock;
			}
		}
		candidate = *mission;
		candidate.event_sequence = event_sequence;
		candidate.trigger = trigger;
		candidate.updated_at_ns = now_ns;
		candidate.state = M98_MISSION_PROPOSAL_REQUIRED;
		candidate.decision = 0;
		memcpy(candidate.working_state_digest, working_digest, M98_DIGEST_SIZE);
		memcpy(candidate.world_state_digest, world_digest, M98_DIGEST_SIZE);
		memcpy(candidate.resource_state_digest, resource_digest, M98_DIGEST_SIZE);
		result = copy_text(candidate.last_event, sizeof(candidate.last_event), event, 0);
		if (result == M98_OK)
			result = append_mission(service, &candidate);
		if (result == M98_OK) {
			*mission = candidate;
			*out = candidate;
		}
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m98_propose(struct m98_service *service, uint64_t mission_id,
			uint64_t now_ns, const struct fts_authority_ref *authority,
			const uint8_t plan_digest[M98_DIGEST_SIZE],
			const uint8_t model_provenance_digest[M98_DIGEST_SIZE],
			const uint8_t action_digest[M98_DIGEST_SIZE],
			uint32_t risk_class, uint32_t resource_mask,
			uint64_t resource_admission, const char *plan,
			const char *action, struct m98_mission *out)
{
	struct m98_mission *mission;
	struct m98_mission candidate;
	struct fts_branch branch;
	int result;

	if (!service || !mission_id || !now_ns || !authority || !plan_digest ||
	    !model_provenance_digest || !action_digest || !nonzero_digest(plan_digest) ||
	    !nonzero_digest(model_provenance_digest) || !nonzero_digest(action_digest) ||
	    !resource_mask || !resource_admission || !plan || !*plan || !action ||
	    !*action || strlen(plan) >= M98_MAX_PLAN || risk_class > 1000000U || !out)
		return M98_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M98_OK)
		return result;
	mission = find_mission(service, mission_id);
	if (!mission) {
		result = M98_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if (mission->state != M98_MISSION_PROPOSAL_REQUIRED) {
		result = mission_terminal(mission) ? M98_ERR_ESCALATED : M98_ERR_STATE;
		goto out_unlock;
	}
	result = mission_policy_check(mission, now_ns);
	if (result != M98_OK) {
		candidate = *mission;
		set_terminal_reason(&candidate, result);
		candidate.updated_at_ns = now_ns;
		(void)copy_text(candidate.reason, sizeof(candidate.reason),
				"mission policy denied proposal", 0);
		if (append_mission(service, &candidate) == M98_OK) {
			*mission = candidate;
			*out = candidate;
		}
		goto out_unlock;
	}
	if (risk_class > mission->risk_ceiling ||
	    !mission->supervisor_nonce || !mission->operator_nonce ||
	    mission->supervisor_nonce == mission->operator_nonce) {
		result = M98_ERR_POLICY;
		goto out_unlock;
	}
	result = fts_branch_propose(&service->tasks, mission->task_id, authority,
			AGI_LC_INTENT_OP_TOOL, resource_mask, resource_admission,
			action_digest, mission->world_state_digest, action, &branch);
	if (result != FTS_OK)
		goto authority_failure;
	result = fts_branch_prepare(&service->tasks, branch.branch_id, now_ns,
			&branch);
	if (result != FTS_OK)
		goto authority_failure;
	candidate = *mission;
	candidate.branch_id = branch.branch_id;
	candidate.state = M98_MISSION_EXECUTION_PENDING;
	candidate.updated_at_ns = now_ns;
	candidate.next_wakeup_ns = now_ns + 5000000000ULL;
	candidate.risk_class = risk_class;
	memcpy(candidate.plan_digest, plan_digest, M98_DIGEST_SIZE);
	memcpy(candidate.model_provenance_digest, model_provenance_digest,
	       M98_DIGEST_SIZE);
	memcpy(candidate.action_digest, action_digest, M98_DIGEST_SIZE);
	result = copy_text(candidate.plan, sizeof(candidate.plan), plan, 0);
	if (result == M98_OK)
		result = append_mission(service, &candidate);
	if (result == M98_OK) {
		*mission = candidate;
		*out = candidate;
	}
	goto out_unlock;
authority_failure:
	candidate = *mission;
	/* A rejected proposal is not itself a mission failure.  Preserve the
	 * proposal-required state so a separately authorized broker can retry. */
	candidate.state = M98_MISSION_PROPOSAL_REQUIRED;
	candidate.decision = 0;
	candidate.escalation_reason = 0;
	candidate.updated_at_ns = now_ns;
	(void)copy_text(candidate.reason, sizeof(candidate.reason),
			"authority or branch preparation denied; no action authorized", 0);
	if (append_mission(service, &candidate) == M98_OK) {
		*mission = candidate;
		*out = candidate;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m98_execute_result(struct m98_service *service, uint64_t mission_id,
			       uint64_t now_ns, uint64_t cpu_used_ns,
			       uint64_t money_used_micro, uint32_t decision,
			       uint32_t verification_ok, const char *result_text,
			       struct m98_mission *out)
{
	struct m98_mission *mission;
	struct m98_mission candidate;
	struct fts_branch branch;
	uint8_t result_digest[M98_DIGEST_SIZE];
	uint8_t verification_digest[M98_DIGEST_SIZE];
	struct fts_continuity capsule;
	int result;

	if (!service || !mission_id || !now_ns || decision < M98_DECISION_CONTINUE ||
	    decision > M98_DECISION_SUCCEED || verification_ok > 1 || !result_text ||
	    !*result_text || strlen(result_text) >= M98_MAX_EVENT || !out)
		return M98_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M98_OK)
		return result;
	mission = find_mission(service, mission_id);
	if (!mission) {
		result = M98_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if (mission->state != M98_MISSION_EXECUTION_PENDING) {
		result = mission_terminal(mission) ? M98_ERR_ESCALATED : M98_ERR_STATE;
		goto out_unlock;
	}
	candidate = *mission;
	candidate.consumed_cpu_ns += cpu_used_ns;
	candidate.consumed_money_micro += money_used_micro;
	candidate.updated_at_ns = now_ns;
	result = mission_policy_check(&candidate, now_ns);
	if (result != M98_OK) {
		set_terminal_reason(&candidate, result);
		(void)copy_text(candidate.reason, sizeof(candidate.reason),
				"execution exceeded mission policy", 0);
		if (append_mission(service, &candidate) == M98_OK) {
			*mission = candidate;
			*out = candidate;
		}
		goto out_unlock;
	}
	if (fts_branch_query(&service->tasks, mission->branch_id, &branch) != FTS_OK) {
		result = M98_ERR_AUTHORITY;
		goto execution_failure;
	}
	result = digest_text(result_text, result_digest);
	if (result != M98_OK)
		goto execution_failure;
	result = fts_branch_add_evidence(&service->tasks, mission->branch_id,
			FTS_EVIDENCE_OBSERVATION, mission->world_state_digest, 1,
			"mission observation accepted", &branch);
	if (result != FTS_OK)
		goto execution_failure;
	result = fts_branch_add_evidence(&service->tasks, mission->branch_id,
			FTS_EVIDENCE_RESULT, result_digest, 1,
			"tool execution result recorded", &branch);
	if (result != FTS_OK)
		goto execution_failure;
	result = digest_text(verification_ok ? "verification:pass" : "verification:fail",
			verification_digest);
	if (result != M98_OK)
		goto execution_failure;
	result = fts_branch_add_evidence(&service->tasks, mission->branch_id,
			FTS_EVIDENCE_VERIFICATION, verification_digest, verification_ok,
			verification_ok ? "independent verification passed" :
			"independent verification failed", &branch);
	if (result != FTS_OK)
		goto execution_failure;
	if (!verification_ok) {
		(void)fts_branch_invalidate(&service->tasks, mission->branch_id,
				FTS_STOP_RISK, &branch);
		result = M98_ERR_EVIDENCE;
		goto execution_failure;
	}
	result = fts_branch_commit(&service->tasks, mission->branch_id, now_ns,
			&branch);
	if (result != FTS_OK)
		goto execution_failure;
	result = fts_continuity_seal(&service->tasks, mission->branch_id, now_ns,
			candidate.working_state_digest, candidate.world_state_digest,
			candidate.resource_state_digest, &capsule);
	if (result != FTS_OK)
		goto execution_failure;
	candidate.branch_id = branch.branch_id;
	candidate.capsule_id = capsule.capsule_id;
	candidate.step++;
	candidate.decision = decision;
	(void)copy_text(candidate.last_event, sizeof(candidate.last_event),
			result_text, 0);
	switch (decision) {
	case M98_DECISION_CONTINUE:
		candidate.state = M98_MISSION_OBSERVE_REQUIRED;
		break;
	case M98_DECISION_REPLAN:
		candidate.state = M98_MISSION_REPLAN_REQUIRED;
		break;
	case M98_DECISION_SUCCEED:
		candidate.state = M98_MISSION_SUCCEEDED;
		break;
	case M98_DECISION_STOP:
		candidate.state = M98_MISSION_STOPPED;
		candidate.stop_reason = M98_REASON_POLICY;
		break;
	case M98_DECISION_ESCALATE:
	default:
		candidate.state = M98_MISSION_ESCALATED;
		candidate.escalation_reason = M98_REASON_POLICY;
		break;
	}
	result = append_mission(service, &candidate);
	if (result == M98_OK) {
		*mission = candidate;
		*out = candidate;
	}
	goto out_unlock;
execution_failure:
	candidate = *mission;
	candidate.state = M98_MISSION_ESCALATED;
	candidate.decision = M98_DECISION_ESCALATE;
	candidate.escalation_reason = result == M98_ERR_EVIDENCE ?
		M98_REASON_VERIFICATION : M98_REASON_AUTHORITY;
	candidate.updated_at_ns = now_ns;
	(void)copy_text(candidate.reason, sizeof(candidate.reason),
			"execution did not produce an evidence-complete committed branch", 0);
	if (append_mission(service, &candidate) == M98_OK) {
		*mission = candidate;
		*out = candidate;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m98_tick(struct m98_service *service, uint64_t mission_id,
		    uint64_t now_ns, struct m98_mission *out)
{
	struct m98_mission *mission;
	struct m98_mission candidate;
	int result;

	if (!service || !mission_id || !now_ns || !out)
		return M98_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M98_OK)
		return result;
	mission = find_mission(service, mission_id);
	if (!mission) {
		result = M98_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if (mission_terminal(mission)) {
		*out = *mission;
		result = M98_OK;
		goto out_unlock;
	}
	result = mission_policy_check(mission, now_ns);
	if (result != M98_OK) {
		candidate = *mission;
		set_terminal_reason(&candidate, result);
		candidate.updated_at_ns = now_ns;
		(void)copy_text(candidate.reason, sizeof(candidate.reason),
				"mission tick enforced deterministic stop", 0);
		result = append_mission(service, &candidate);
		if (result == M98_OK) {
			*mission = candidate;
			*out = candidate;
			result = candidate.stop_reason == M98_REASON_DEADLINE ?
				M98_ERR_DEADLINE : M98_ERR_BUDGET;
		}
		goto out_unlock;
	}
	*out = *mission;
	result = M98_OK;
out_unlock:
	unlock_service(service);
	return result;
}

int m98_query(const struct m98_service *service, uint64_t mission_id,
		      struct m98_mission *out)
{
	struct m98_service *mutable_service = (struct m98_service *)service;
	struct m98_mission *mission;
	int result;

	if (!service || !mission_id || !out)
		return M98_ERR_ARGUMENT;
	result = lock_service(mutable_service);
	if (result != M98_OK)
		return result;
	mission = find_mission(mutable_service, mission_id);
	if (!mission)
		result = M98_ERR_NOT_FOUND;
	else {
		*out = *mission;
		result = M98_OK;
	}
	unlock_service(mutable_service);
	return result;
}

int m98_test_corrupt_tail(const struct m98_service *service)
{
	struct m98_service *mutable_service = (struct m98_service *)service;
	unsigned char corrupt = 0xff;
	int result;

	if (!service)
		return M98_ERR_ARGUMENT;
	result = lock_service(mutable_service);
	if (result != M98_OK)
		return result;
	if (write_all(mutable_service->mission_fd, &corrupt, sizeof(corrupt)) ==
	    M98_OK && fdatasync(mutable_service->mission_fd) == 0)
		result = M98_OK;
	else
		result = M98_ERR_IO;
	unlock_service(mutable_service);
	return result;
}
