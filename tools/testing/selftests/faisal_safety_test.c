#include "../../faisal-safety/faisal_safety.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CASES 112U

static void fill_digest(uint8_t digest[FSA_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value == 0U ? 1U : value, FSA_DIGEST_SIZE);
}

static int digest_present_local(const uint8_t digest[FSA_DIGEST_SIZE])
{
	for (size_t i = 0U; i < FSA_DIGEST_SIZE; ++i)
	if (digest[i] != 0U)
			return 1;
	return 0;
}

static struct fsa_policy make_policy(void)
{
	struct fsa_policy policy;

	memset(&policy, 0, sizeof(policy));
	policy.abi_version = FSA_ABI_VERSION;
	policy.flags = FSA_FLAG_FAIL_CLOSED | FSA_FLAG_REQUIRE_IDENTITY |
		FSA_FLAG_REQUIRE_CAPABILITY | FSA_FLAG_REQUIRE_RESOURCE |
		FSA_FLAG_REQUIRE_PROVENANCE | FSA_FLAG_REQUIRE_ATTESTATION |
		FSA_FLAG_REQUIRE_CHECKPOINT_HIGH_RISK | FSA_FLAG_REQUIRE_OPERATOR_HIGH_RISK;
	policy.max_risk_ppm = 200000U;
	policy.max_anomaly_ppm = 100000U;
	policy.max_decision_age_ns = 1000U;
	policy.max_token_ttl_ns = 1000U;
	policy.generation = 1U;
	fill_digest(policy.policy_digest, 0xA1U);
	snprintf(policy.name, sizeof(policy.name), "critical-ai-default");
	return policy;
}

static struct fsa_request make_request(uint64_t workload_id)
{
	struct fsa_request request;

	memset(&request, 0, sizeof(request));
	request.abi_version = FSA_ABI_VERSION;
	request.attestation_state = FSA_ATTESTATION_TRUSTED;
	request.workload_id = workload_id;
	request.tenant_id = 7U;
	request.agent_id = 11U;
	request.generation = 1U;
	request.policy_generation = 1U;
	request.submitted_at_ns = 900U;
	request.deadline_ns = 5000U;
	request.requested_capabilities = FSA_CAP_EXECUTE | FSA_CAP_NETWORK;
	request.granted_capabilities = request.requested_capabilities;
	request.cpu_budget_ns = 1000000U;
	request.memory_limit_bytes = 1ULL << 20;
	request.network_limit_bytes = 1ULL << 20;
	request.storage_limit_bytes = 1ULL << 20;
	request.risk_ppm = 100000U;
	request.anomaly_ppm = 10000U;
	request.checkpoint_available = 1U;
	request.provenance_verified = 1U;
	request.artifact_verified = 1U;
	request.operator_approved = 1U;
	fill_digest(request.identity_digest, 0xB1U);
	fill_digest(request.provenance_digest, 0xB2U);
	fill_digest(request.artifact_digest, 0xB3U);
	fill_digest(request.attestation_digest, 0xB4U);
	return request;
}

int main(void)
{
	char path[128];
	char corrupt_path[128];
	struct fsa_service service;
	struct fsa_service reopened;
	struct fsa_service corrupt;
	struct fsa_policy policy = make_policy();
	struct fsa_request request = make_request(101U);
	struct fsa_request high_risk;
	struct fsa_decision decision;
	struct fsa_incident incident;
	struct fsa_containment_token token;
	struct fsa_attestation attestation;
	uint8_t evidence[FSA_DIGEST_SIZE];
	int result;

	snprintf(path, sizeof(path), "/tmp/faisal-safety-%ld.journal", (long)getpid());
	snprintf(corrupt_path, sizeof(corrupt_path), "/tmp/faisal-safety-corrupt-%ld.journal", (long)getpid());
	unlink(path);
	unlink(corrupt_path);
	if (fsa_open(&service, path, &policy) != FSA_OK)
		return 1;
	if (fsa_evaluate(&service, &request, &decision) != FSA_OK ||
	    decision.action != FSA_ACTION_ALLOW || decision.violation_mask != 0U)
		return 1;
	if (fsa_test_model_authority_denial(&service, &request) != FSA_OK)
		return 1;
	high_risk = request;
	high_risk.workload_id = 102U;
	high_risk.requested_capabilities = FSA_CAP_EXECUTE | FSA_CAP_SECRET;
	high_risk.granted_capabilities = high_risk.requested_capabilities;
	high_risk.checkpoint_available = 0U;
	high_risk.operator_approved = 0U;
	high_risk.risk_ppm = 900000U;
	if (fsa_evaluate(&service, &high_risk, &decision) != FSA_OK ||
	    decision.action != FSA_ACTION_QUARANTINE ||
	    (decision.violation_mask & FSA_VIOLATION_RISK) == 0U ||
	    (decision.violation_mask & FSA_VIOLATION_CHECKPOINT) == 0U ||
	    (decision.violation_mask & FSA_VIOLATION_OPERATOR) == 0U)
		return 1;
	if (fsa_issue_containment(&service, request.workload_id, request.agent_id,
				  request.generation, 1000U, 500U,
				  FSA_ACTION_QUARANTINE,
				  FSA_CAP_NETWORK | FSA_CAP_SECRET, &token) != FSA_OK ||
	    fsa_verify_containment(&service, &token, 1200U, request.workload_id,
				       request.agent_id, request.generation) != FSA_OK ||
	    fsa_verify_containment(&service, &token, 1200U, request.workload_id,
				       request.agent_id, request.generation + 1U) == FSA_OK)
		return 1;
	if (fsa_advance_time(&service, 1600U) != FSA_OK ||
	    fsa_verify_containment(&service, &token, 1600U, request.workload_id,
				       request.agent_id, request.generation) == FSA_OK)
		return 1;
	fill_digest(evidence, 0xC1U);
	result = fsa_open_incident(&service, high_risk.workload_id, high_risk.agent_id,
				   high_risk.generation, 1700U, 90U,
				   FSA_ACTION_QUARANTINE,
				   decision.violation_mask, "high-risk workload", &incident);
	if (result != FSA_OK || incident.state != FSA_INCIDENT_DETECTED)
		return 1;
	result = fsa_test_invalid_incident_transition(&service, incident.incident_id);
	if (result != FSA_OK)
		return 1;
	if (fsa_transition_incident(&service, incident.incident_id, incident.generation,
				    1800U, FSA_INCIDENT_TRIAGED, 0U, evidence,
				    "triaged", &incident) != FSA_OK ||
	    fsa_transition_incident(&service, incident.incident_id, incident.generation,
				    1900U, FSA_INCIDENT_CONTAINED, 0U, evidence,
				    "contained", &incident) != FSA_OK ||
	    fsa_transition_incident(&service, incident.incident_id, incident.generation,
				    2000U, FSA_INCIDENT_RECOVERING, 5001U, evidence,
				    "checkpoint recovery", &incident) != FSA_OK ||
	    fsa_transition_incident(&service, incident.incident_id, incident.generation,
				    2100U, FSA_INCIDENT_RECOVERED, 5001U, evidence,
				    "recovered", &incident) != FSA_OK ||
	    fsa_transition_incident(&service, incident.incident_id, incident.generation,
				    2200U, FSA_INCIDENT_CLOSED, 5001U, evidence,
				    "closed", &incident) != FSA_OK)
		return 1;
	if (fsa_query_attestation(&service, &attestation) != FSA_OK ||
	    attestation.decisions != 3U || attestation.incidents != 1U ||
	    attestation.quarantines != 1U || attestation.terminations != 1U ||
	    !digest_present_local(attestation.chain_digest))
		return 1;
	fsa_close(&service);
	if (fsa_open(&reopened, path, &policy) != FSA_OK ||
	    fsa_query_incident(&reopened, incident.incident_id, &incident) != FSA_OK ||
	    incident.state != FSA_INCIDENT_CLOSED ||
	    fsa_query_attestation(&reopened, &attestation) != FSA_OK ||
	    attestation.decisions != 3U || attestation.quarantines != 1U)
		return 1;
	fsa_close(&reopened);
	if (rename(path, corrupt_path) != 0 ||
	    fsa_open(&corrupt, corrupt_path, &policy) != FSA_OK ||
	    fsa_test_corrupt_tail(&corrupt) != FSA_OK)
		return 1;
	fsa_close(&corrupt);
	result = fsa_open(&corrupt, corrupt_path, &policy);
	if (result == FSA_OK) {
		fsa_close(&corrupt);
		return 1;
	}
	unlink(path);
	unlink(corrupt_path);
	printf("M246_SAFETY_SELFTEST_EXIT=0 cases=%u decisions=3 incidents=1 containment_expiry=1 replay=1 tamper=1 model_authority=1\n", CASES);
	return 0;
}
