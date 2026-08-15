#ifndef FAISAL_EXPERIENCE_SERVICE_H
#define FAISAL_EXPERIENCE_SERVICE_H

#include <stdint.h>
#include "../faisal-memory/faisal_memory_service.h"

#define FES_MAX_EXPERIENCES 32
#define FES_MAX_KEY 128
#define FES_MAX_SKILL 512

enum fes_state {
	FES_RECORDED = 1,
	FES_EVALUATED = 2,
	FES_REUSABLE = 3,
	FES_CORRECTED = 4,
	FES_REJECTED = 5,
	FES_EXPIRED = 6
};

struct fes_item {
	uint64_t key_hash;
	uint64_t experience_sequence;
	uint64_t memory_record_id;
	uint64_t memory_capability;
	uint64_t artifact_id;
	uint64_t artifact_capability;
	uint32_t state;
	uint32_t confidence_ppm;
	uint8_t content_digest[FMS_DIGEST_SIZE];
	char key[FES_MAX_KEY];
	char content[FMS_MAX_CONTENT];
	char skill[FES_MAX_SKILL];
};

struct fes_service {
	struct fms_service memory;
	struct fes_item items[FES_MAX_EXPERIENCES];
	uint32_t count;
};

int fes_open(struct fes_service *service, const char *journal_path);
void fes_close(struct fes_service *service);
int fes_record_and_evaluate(struct fes_service *service, const char *key,
			    const char *content, const char *skill,
			    int verified, struct fes_item *out);
int fes_retrieve_reusable(struct fes_service *service, const char *key,
			  struct fes_item *out);
int fes_record_reuse(struct fes_service *service, const struct fes_item *item);
int fes_correct(struct fes_service *service, struct fes_item *item,
		const char *corrected_content, const char *corrected_skill);
int fes_test_stale_artifact(struct fes_service *service,
			    const struct fes_item *item);

#endif
