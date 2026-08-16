#include "faisal_runtime_attestation.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int nonzero_u64(uint64_t value)
{
	return value != 0;
}

int fra_open(struct fra_service *service)
{
	struct agi_lc_create create;
	struct agi_lc_agent selected;

	if (!service)
		return FRA_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->kernel_fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (service->kernel_fd < 0)
		return FRA_ERR_OPEN;
	memset(&create, 0, sizeof(create));
	create.size = sizeof(create);
	if (ioctl(service->kernel_fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(service->kernel_fd, AGI_LC_ATTACH_TASK) < 0)
		goto fail;
	memset(&service->identity, 0, sizeof(service->identity));
	service->identity.size = sizeof(service->identity);
	service->identity.role = AGI_LC_LIGHT_AGENT_ROLE_VERIFIER;
	service->identity.workload = AGI_LC_WORKLOAD_VERIFICATION;
	service->identity.priority = 0;
	service->identity.resource_mask = 0;
	service->identity.event_mask = 0;
	service->identity.correlation = 86001;
	if (ioctl(service->kernel_fd, AGI_LC_LIGHT_AGENT_REGISTER,
		  &service->identity) < 0 || !service->identity.agent_id ||
	    !service->identity.capability)
		goto fail;
	memset(&selected, 0, sizeof(selected));
	selected.size = sizeof(selected);
	selected.agent_id = service->identity.agent_id;
	selected.correlation = 86002;
	if (ioctl(service->kernel_fd, AGI_LC_SET_AGENT, &selected) < 0)
		goto fail;
	service->session_id = create.session_id;
	service->agent_id = service->identity.agent_id;
	service->capability = service->identity.capability;
	return FRA_OK;
fail:
	close(service->kernel_fd);
	service->kernel_fd = -1;
	return FRA_ERR_IOCTL;
}

void fra_close(struct fra_service *service)
{
	struct agi_lc_light_agent identity;
	if (!service || service->kernel_fd < 0)
		return;
	identity = service->identity;
	if (identity.agent_id)
		(void)ioctl(service->kernel_fd, AGI_LC_LIGHT_AGENT_UNREGISTER, &identity);
	close(service->kernel_fd);
	service->kernel_fd = -1;
}

int fra_sample(struct fra_service *service)
{
	struct agi_lc_self_state *self_state;
	struct agi_lc_resource_snapshot *resource;
	struct agi_lc_observability *observability;
	uint32_t valid = 0;

	if (!service || service->kernel_fd < 0)
		return FRA_ERR_ARGUMENT;
	memset(&service->attestation, 0, sizeof(service->attestation));
	self_state = &service->attestation.self_state;
	self_state->size = sizeof(*self_state);
	if (ioctl(service->kernel_fd, AGI_LC_GET_SELF_STATE, self_state) == 0)
		valid |= FRA_HEALTH_SELF_STATE;
	resource = &service->attestation.resource;
	resource->size = sizeof(*resource);
	resource->correlation = 86003;
	if (ioctl(service->kernel_fd, AGI_LC_GET_RESOURCE_SNAPSHOT, resource) == 0)
		valid |= FRA_HEALTH_RESOURCE;
	observability = &service->attestation.observability;
	observability->size = sizeof(*observability);
	observability->operation = AGI_LC_OBSERVABILITY_QUERY;
	observability->correlation = 86004;
	if (ioctl(service->kernel_fd, AGI_LC_OBSERVABILITY, observability) == 0)
		valid |= FRA_HEALTH_OBSERVABILITY;
	service->attestation.identity = service->identity;
	if (nonzero_u64(service->identity.agent_id) &&
	    nonzero_u64(service->identity.capability))
		valid |= FRA_HEALTH_IDENTITY | FRA_HEALTH_CAPABILITY;
	if (resource->cpu_budget_ns || resource->memory_limit_bytes)
		valid |= FRA_HEALTH_BUDGET;
	service->attestation.valid_mask = valid;
	service->attestation.sampled_at_ns = resource->sampled_at_ns;
	service->attestation.sample_sequence = resource->generation;
	return (valid & FRA_SAMPLE_REQUIRED_MASK) == FRA_SAMPLE_REQUIRED_MASK ?
		FRA_OK : FRA_ERR_IOCTL;
}

int fra_compute_digest(struct fra_service *service)
{
	EVP_MD_CTX *ctx;
	unsigned int length = 0;
	int ret = FRA_ERR_DIGEST;

	if (!service)
		return FRA_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FRA_ERR_DIGEST;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, &service->attestation.valid_mask,
			     sizeof(service->attestation.valid_mask)) == 1 &&
	    EVP_DigestUpdate(ctx, &service->attestation.self_state,
			     sizeof(service->attestation.self_state)) == 1 &&
	    EVP_DigestUpdate(ctx, &service->attestation.resource,
			     sizeof(service->attestation.resource)) == 1 &&
	    EVP_DigestUpdate(ctx, &service->attestation.observability,
			     sizeof(service->attestation.observability)) == 1 &&
	    EVP_DigestUpdate(ctx, &service->attestation.identity,
			     sizeof(service->attestation.identity)) == 1 &&
	    EVP_DigestFinal_ex(ctx, service->attestation.digest, &length) == 1 &&
	    length == FRA_DIGEST_SIZE)
		ret = FRA_OK;
	EVP_MD_CTX_free(ctx);
	return ret;
}

int fra_evaluate(struct fra_service *service)
{
	uint32_t valid;
	uint32_t health = 0;
	const struct agi_lc_self_state *self_state;
	const struct agi_lc_resource_snapshot *resource;
	const struct agi_lc_observability *observability;

	if (!service)
		return FRA_ERR_ARGUMENT;
	valid = service->attestation.valid_mask;
	self_state = &service->attestation.self_state;
	resource = &service->attestation.resource;
	observability = &service->attestation.observability;
	if ((valid & FRA_SAMPLE_REQUIRED_MASK) != FRA_SAMPLE_REQUIRED_MASK) {
		service->attestation.state = FRA_STATE_UNAVAILABLE;
		return FRA_ERR_HEALTH;
	}
	health |= FRA_HEALTH_SELF_STATE | FRA_HEALTH_RESOURCE |
		  FRA_HEALTH_OBSERVABILITY | FRA_HEALTH_IDENTITY |
		  FRA_HEALTH_CAPABILITY;
	if (valid & FRA_HEALTH_BUDGET)
		health |= FRA_HEALTH_BUDGET;
	service->attestation.health_mask = health;
	service->attestation.state = FRA_STATE_HEALTHY;
	if (self_state->failed_count || self_state->cancelled_count ||
	    resource->network_denied || observability->dropped)
		service->attestation.state = FRA_STATE_DEGRADED;
	return FRA_OK;
}

int fra_run(struct fra_service *service)
{
	if (fra_sample(service) != FRA_OK)
		return FRA_ERR_IOCTL;
	if (fra_compute_digest(service) != FRA_OK)
		return FRA_ERR_DIGEST;
	return fra_evaluate(service);
}
