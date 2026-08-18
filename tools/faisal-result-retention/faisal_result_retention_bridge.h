#ifndef FAISAL_RESULT_RETENTION_BRIDGE_H
#define FAISAL_RESULT_RETENTION_BRIDGE_H

#include "faisal_result_retention.h"
#include "../faisal-result-verify/faisal_result_verify.h"

int rdr_import_fsv_result(struct rdr_service *retention,
	const struct fsv_service *verification, uint64_t result_id,
	const struct rdr_policy *policy, struct rdr_event *out);
int rdr_commit_fsv_result(struct rdr_service *retention,
	const struct fsv_service *verification, uint64_t result_id,
	const uint8_t transition_digest[RDR_DIGEST_SIZE],
	const struct rdr_policy *policy, struct rdr_event *out);

#endif
