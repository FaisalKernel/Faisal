#define _GNU_SOURCE
#include "faisal_autonomy_orchestrator.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static uint64_t m105_now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int m105_attach(int fd)
{
	return fd >= 0 && ioctl(fd, AGI_LC_ATTACH_TASK) == 0 ? 0 : -1;
}

static void m105_copy_text(char *dst, size_t dst_size, const char *src)
{
	if (!dst || !dst_size)
		return;
	if (!src)
		src = "";
	snprintf(dst, dst_size, "%s", src);
}

int m105_open(struct m105_service *service, const char *journal_prefix,
		      const char *kernel_device)
{
	char path[512];
	int ret;

	if (!service || !journal_prefix || !kernel_device || !*kernel_device)
		return M105_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->kernel_fd = -1;
	service->next_sequence = 1;

	ret = m77_open(&service->research, journal_prefix);
	if (ret)
		return ret;
	ret = fes_open(&service->experience, journal_prefix);
	if (ret)
		goto fail_research;
	snprintf(path, sizeof(path), "%s.self-healing", journal_prefix);
	ret = fas_open(&service->healing, path);
	if (ret)
		goto fail_experience;

	ret = M105_ERR_KERNEL;
	(void)kernel_device;
	service->kernel_fd = service->research.browser.memory.kernel_fd;
	if (service->kernel_fd < 0)
		goto fail_healing;
	{
		struct agi_lc_autonomy_control control;
		memset(&control, 0, sizeof(control));
		control.size = sizeof(control);
		control.operation = AGI_LC_AUTONOMY_CREATE;
		control.flags = AGI_LC_AUTONOMY_FLAG_REQUIRE_SIGNED_EVIDENCE |
			       AGI_LC_AUTONOMY_FLAG_REQUIRE_SUPERVISOR |
			       AGI_LC_AUTONOMY_FLAG_REQUIRE_OPERATOR;
		control.required_evidence_mask = AGI_LC_AUTONOMY_EVIDENCE_ALL;
		if (ioctl(service->kernel_fd, AGI_LC_AUTONOMY_CONTROL,
			  &control) != 0) {
			close(service->kernel_fd);
			service->kernel_fd = -1;
			goto fail_healing;
		}
		service->kernel_control = control;
		service->kernel_bound = 1;
	}
	return M105_OK;

fail_healing:
	fas_close(&service->healing);
fail_experience:
	fes_close(&service->experience);
fail_research:
	m77_close(&service->research);
	return ret;
}

void m105_close(struct m105_service *service)
{
	struct agi_lc_autonomy_control control;

	if (!service)
		return;
	if (service->kernel_bound && service->kernel_fd >= 0) {
		control = service->kernel_control;
		control.size = sizeof(control);
		control.operation = AGI_LC_AUTONOMY_CLOSE;
		(void)ioctl(service->kernel_fd, AGI_LC_AUTONOMY_CONTROL, &control);
	}
	/* The M77/FMS stack owns this session fd and closes it below. */
	service->kernel_fd = -1;
	fas_close(&service->healing);
	fes_close(&service->experience);
	m77_close(&service->research);
	memset(service, 0, sizeof(*service));
	service->kernel_fd = -1;
}

int m105_observe_verify_learn(struct m105_service *service,
			      const char *claim,
			      const char *primary_uri,
			      const char *primary_content,
			      const char *secondary_uri,
			      const char *secondary_content,
			      struct m105_cycle *out)
{
	struct m77_source primary, secondary;
	struct fws_fact fact;
	struct fes_item experience;
	struct m105_cycle cycle;
	uint64_t sequence;
	int ret;

	if (!service || !claim || !primary_uri || !primary_content ||
	    !secondary_uri || !secondary_content || !out)
		return M105_ERR_ARGUMENT;
	if (service->cycle_count >= M105_MAX_CYCLES)
		return M105_ERR_LIMIT;
	memset(&cycle, 0, sizeof(cycle));
	sequence = service->next_sequence++;
	cycle.sequence = sequence;
	cycle.started_ns = m105_now_ns();
	m105_copy_text(cycle.claim, sizeof(cycle.claim), claim);

	ret = m77_collect(&service->research, claim, primary_uri, primary_content,
			  M77_SOURCE_KIND_PRIMARY, 1, 900000, 0,
			  AGI_LC_KNOWLEDGE_MAX_TTL_NS, &primary);
	if (ret)
		goto fail;
	ret = m77_collect(&service->research, claim, secondary_uri,
			  secondary_content, M77_SOURCE_KIND_SECONDARY, 2, 600000,
			  0, AGI_LC_KNOWLEDGE_MAX_TTL_NS, &secondary);
	if (ret)
		goto fail;
	cycle.source_id = primary.source_id;
	cycle.related_source_id = secondary.source_id;
	cycle.evidence_mask |= AGI_LC_AUTONOMY_EVIDENCE_OBSERVATION;

	ret = m77_crosscheck(&service->research, primary.source_id,
			     secondary.source_id);
	if (ret)
		goto fail;
	if (m105_attach(service->research.browser.memory.kernel_fd) < 0)
		goto fail;
	ret = m77_verify(&service->research, primary.source_id,
			 primary.content_digest);
	if (ret)
		goto fail;
	ret = m77_verify(&service->research, secondary.source_id,
			 secondary.content_digest);
	if (ret)
		goto fail;
	cycle.evidence_mask |= AGI_LC_AUTONOMY_EVIDENCE_SECURITY;
	if (m105_attach(service->research.world.memory.kernel_fd) < 0)
		goto fail;
	ret = m77_promote_verified(&service->research, primary.source_id, &fact);
	if (ret)
		goto fail;
	cycle.verified = 1;
	cycle.promoted = 1;
	cycle.evidence_mask |= AGI_LC_AUTONOMY_EVIDENCE_TEST;
	memcpy(cycle.evidence_digest, primary.content_digest,
	       sizeof(cycle.evidence_digest));
	ret = m105_record_kernel_evidence(service, cycle.evidence_mask,
					  cycle.evidence_digest);
	if (ret)
		goto fail;

	if (m105_attach(service->experience.memory.kernel_fd) < 0)
		goto fail;
	ret = fes_record_and_evaluate(&service->experience, claim,
				      primary.content,
				      "verified-source-reuse",
				      cycle.verified, &experience);
	if (ret)
		goto fail;
	cycle.memory_record_id = experience.memory_record_id;
	cycle.experience_sequence = experience.experience_sequence;
	cycle.completed_ns = m105_now_ns();
	cycle.status = M105_OK;
	service->cycles[service->cycle_count++] = cycle;
	*out = cycle;
	return M105_OK;

fail:
	cycle.completed_ns = m105_now_ns();
	cycle.status = ret;
	*out = cycle;
	return ret == 0 ? M105_ERR_UNVERIFIED : ret;
}

int m105_record_kernel_evidence(struct m105_service *service,
				uint32_t evidence_mask,
				const uint8_t evidence_digest[FMS_DIGEST_SIZE])
{
	struct agi_lc_autonomy_control control;

	if (!service || !evidence_digest)
		return M105_ERR_ARGUMENT;
	if (!service->kernel_bound || service->kernel_fd < 0)
		return M105_ERR_KERNEL;
	if ((evidence_mask & ~AGI_LC_AUTONOMY_EVIDENCE_ALL) != 0)
		return M105_ERR_ARGUMENT;
	if (m105_attach(service->research.browser.memory.kernel_fd) < 0)
		return M105_ERR_KERNEL;
	control = service->kernel_control;
	control.size = sizeof(control);
	control.operation = AGI_LC_AUTONOMY_RECORD_EVIDENCE;
	control.evidence_mask = evidence_mask;
	memcpy(control.evidence_digest, evidence_digest,
	       sizeof(control.evidence_digest));
	if (ioctl(service->kernel_fd, AGI_LC_AUTONOMY_CONTROL, &control) != 0)
		return M105_ERR_KERNEL;
	service->kernel_control = control;
	return control.status ? M105_ERR_POLICY : M105_OK;
}

int m105_query_kernel_gate(struct m105_service *service,
				   struct agi_lc_autonomy_control *out)
{
	struct agi_lc_autonomy_control control;

	if (!service || !out)
		return M105_ERR_ARGUMENT;
	if (!service->kernel_bound || service->kernel_fd < 0)
		return M105_ERR_KERNEL;
	control = service->kernel_control;
	control.size = sizeof(control);
	control.operation = AGI_LC_AUTONOMY_QUERY;
	if (ioctl(service->kernel_fd, AGI_LC_AUTONOMY_CONTROL, &control) != 0)
		return M105_ERR_KERNEL;
	service->kernel_control = control;
	*out = control;
	return control.status ? M105_ERR_STATE : M105_OK;
}

int m105_test_model_output_not_authority(struct m105_service *service)
{
	struct m77_source source;
	int ret;

	if (!service)
		return M105_ERR_ARGUMENT;
	if (m105_attach(service->research.browser.memory.kernel_fd) < 0)
		return M105_ERR_KERNEL;
	ret = m77_collect(&service->research, "untrusted model claim",
			  "https://example.test", "model output remains unverified evidence",
			  M77_SOURCE_KIND_SECONDARY, 99, 100000, 0,
			  AGI_LC_KNOWLEDGE_MAX_TTL_NS, &source);
	if (ret)
		return ret;
	return m77_test_unverified_denial(&service->research, source.source_id) == 0
		? M105_OK : M105_ERR_UNVERIFIED;
}
