#define _GNU_SOURCE
#include "faisal_experience_service.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static uint64_t key_hash(const char *key)
{
	uint64_t hash = 1469598103934665603ULL;
	while (*key) {
		hash ^= (unsigned char)*key++;
		hash *= 1099511628211ULL;
	}
	return hash ? hash : 1;
}

static int digest_bytes(const void *data, size_t len,
			unsigned char digest[FMS_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int out_len = 0;
	int ret = -1;
	if (!ctx)
		return -1;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, data, len) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 &&
	    out_len == FMS_DIGEST_SIZE)
		ret = 0;
	EVP_MD_CTX_free(ctx);
	return ret;
}

static struct fes_item *find_item(struct fes_service *service,
				  uint64_t hash)
{
	uint32_t i;
	for (i = 0; i < service->count; i++)
		if (service->items[i].key_hash == hash)
			return &service->items[i];
	return NULL;
}

int fes_open(struct fes_service *service, const char *journal_path)
{
	if (!service)
		return -1;
	memset(service, 0, sizeof(*service));
	return fms_open(&service->memory, journal_path);
}

void fes_close(struct fes_service *service)
{
	if (service)
		fms_close(&service->memory);
}

static int kernel_experience(struct fes_service *service, const char *content,
			     uint64_t parent_sequence,
			     struct agi_lc_experience_record *out)
{
	struct agi_lc_experience_record experience;
	unsigned char digest[FMS_DIGEST_SIZE];
	size_t len = strlen(content);
	if (!len || len > AGI_LC_EXPERIENCE_MAX ||
	    digest_bytes(content, len, digest) < 0)
		return -1;
	memset(&experience, 0, sizeof(experience));
	experience.size = sizeof(experience);
	experience.kind = AGI_LC_EXPERIENCE_RESULT;
	experience.parent_sequence = parent_sequence;
	experience.correlation = 72010;
	memcpy(experience.action_digest, digest, FMS_DIGEST_SIZE);
	memcpy(experience.observation_digest, digest, FMS_DIGEST_SIZE);
	memcpy(experience.result_digest, digest, FMS_DIGEST_SIZE);
	if (ioctl(service->memory.kernel_fd, AGI_LC_RECORD_EXPERIENCE, &experience) < 0)
		return -1;
	*out = experience;
	return 0;
}

int fes_record_and_evaluate(struct fes_service *service, const char *key,
			    const char *content, const char *skill,
			    int verified, struct fes_item *out)
{
	struct agi_lc_experience_record experience;
	struct agi_lc_learning_artifact artifact;
	struct fms_entry memory;
	struct fes_item item;
	uint64_t hash;
	int ret;

	if (!service || !key || !content || !skill || !*key || !*content ||
	    strlen(key) >= FES_MAX_KEY || strlen(skill) >= FES_MAX_SKILL ||
	    service->count >= FES_MAX_EXPERIENCES)
		return -1;
	hash = key_hash(key);
	if (find_item(service, hash))
		return -2;
	if (kernel_experience(service, content, 0, &experience) < 0)
		return -3;
	ret = fms_put(&service->memory, content, AGI_LC_MEMORY_TIER_EPISODIC,
			  verified ? 900000 : 300000, verified ? 900000 : 200000,
			  experience.experience_sequence, &memory);
	if (ret != FMS_OK)
		return -4;
	memset(&item, 0, sizeof(item));
	item.key_hash = hash;
	item.experience_sequence = experience.experience_sequence;
	item.memory_record_id = memory.record_id;
	item.memory_capability = memory.authority_capability;
	item.state = verified ? FES_EVALUATED : FES_REJECTED;
	item.confidence_ppm = verified ? 900000 : 300000;
	memcpy(item.content_digest, memory.digest, FMS_DIGEST_SIZE);
	strncpy(item.key, key, sizeof(item.key) - 1);
	strncpy(item.content, content, sizeof(item.content) - 1);
	strncpy(item.skill, skill, sizeof(item.skill) - 1);
	if (verified) {
		memset(&artifact, 0, sizeof(artifact));
		artifact.size = sizeof(artifact);
		artifact.kind = AGI_LC_LEARNING_SKILL;
		artifact.experience_sequence = experience.experience_sequence;
		memcpy(artifact.source_digest, memory.digest, FMS_DIGEST_SIZE);
		if (digest_bytes(skill, strlen(skill), artifact.artifact_digest) < 0)
			return -5;
		artifact.correlation = 72011;
		if (ioctl(service->memory.kernel_fd, AGI_LC_PUBLISH_ARTIFACT,
			  &artifact) < 0)
			return -6;
		item.artifact_id = artifact.artifact_id;
		item.artifact_capability = artifact.capability;
		item.state = FES_REUSABLE;
	}
	service->items[service->count++] = item;
	*out = item;
	return 0;
}

int fes_retrieve_reusable(struct fes_service *service, const char *key,
			  struct fes_item *out)
{
	struct fes_item *item;
	if (!service || !key || !out)
		return -1;
	item = find_item(service, key_hash(key));
	if (!item || item->state != FES_REUSABLE)
		return -2;
	*out = *item;
	return 0;
}

int fes_record_reuse(struct fes_service *service, const struct fes_item *item)
{
	struct agi_lc_experience_record experience;
	char payload[AGI_LC_EXPERIENCE_MAX + 1];
	if (!service || !item)
		return -1;
	snprintf(payload, sizeof(payload), "reuse:%s", item->key);
	if (kernel_experience(service, payload, item->experience_sequence,
			      &experience) < 0)
		return -2;
	return 0;
}

int fes_correct(struct fes_service *service, struct fes_item *item,
		const char *corrected_content, const char *corrected_skill)
{
	struct fes_item corrected;
	struct fes_item *indexed;
	uint64_t hash;
	if (!service || !item || !corrected_content || !corrected_skill)
		return -1;
	hash = key_hash(item->key);
	indexed = find_item(service, hash);
	if (!indexed)
		return -2;
	indexed->state = FES_CORRECTED;
	indexed->key_hash = 0;
	if (fes_record_and_evaluate(service, item->key, corrected_content,
				    corrected_skill, 1, &corrected) != 0)
		return -3;
	*item = corrected;
	return 0;
}

int fes_test_stale_artifact(struct fes_service *service,
			    const struct fes_item *item)
{
	struct agi_lc_learning_artifact artifact;
	if (!service || !item || !item->artifact_id || !item->artifact_capability)
		return -1;
	memset(&artifact, 0, sizeof(artifact));
	artifact.size = sizeof(artifact);
	artifact.artifact_id = item->artifact_id;
	artifact.capability = item->artifact_capability ^ 1ULL;
	artifact.correlation = 72012;
	if (ioctl(service->memory.kernel_fd, AGI_LC_GET_ARTIFACT, &artifact) == 0)
		return -2;
	return errno == EACCES ? 0 : -3;
}
