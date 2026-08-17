#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "M116_PRECISION_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
}

static int setup_session(int fd)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_TESTER,
		.workload = AGI_LC_WORKLOAD_INFERENCE,
		.correlation = 116001,
	};
	struct agi_lc_agent agent = { .size = sizeof(agent) };

	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id)
		return -1;
	agent.agent_id = light.agent_id;
	agent.correlation = 116002;
	return ioctl(fd, AGI_LC_SET_AGENT, &agent);
}

static void fill_digest(__u8 digest[AGI_LC_DIGEST_SIZE], __u8 seed)
{
	unsigned int i;

	for (i = 0; i < AGI_LC_DIGEST_SIZE; i++)
		digest[i] = seed + i;
}

int main(void)
{
	int fd;
	struct agi_lc_verified_knowledge publish = {
		.size = sizeof(publish),
		.operation = AGI_LC_KNOWLEDGE_PUBLISH,
		.flags = AGI_LC_KNOWLEDGE_FLAG_PRIMARY |
			AGI_LC_KNOWLEDGE_FLAG_INTEGRITY_MEASURED |
			AGI_LC_KNOWLEDGE_FLAG_FRESHNESS_REQUIRED,
		.source_id = 116101,
		.source_uri_hash = 116102,
		.source_rank = 1,
		.source_kind = AGI_LC_KNOWLEDGE_SOURCE_PRIMARY,
		.confidence_ppm = 900000,
		.freshness_ttl_ns = AGI_LC_KNOWLEDGE_MAX_TTL_NS,
		.correlation = 116103,
	};
	struct agi_lc_verified_knowledge validate, verify;

	fill_digest(publish.source_digest, 0x10);
	fill_digest(publish.content_digest, 0x40);
	fill_digest(publish.evidence_digest, 0x70);
	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail("open");
	if (setup_session(fd) < 0)
		return fail("session");
	if (ioctl(fd, AGI_LC_KNOWLEDGE, &publish) < 0 ||
	    publish.record_id == 0)
		return fail("publish");

	memset(&validate, 0, sizeof(validate));
	validate.size = sizeof(validate);
	validate.operation = AGI_LC_KNOWLEDGE_VALIDATE;
	validate.flags = AGI_LC_KNOWLEDGE_FLAG_FRESHNESS_REQUIRED;
	validate.record_id = publish.record_id;
	validate.confidence_ppm = 900000;
	validate.correlation = 116104;
	if (ioctl(fd, AGI_LC_KNOWLEDGE, &validate) == 0 || errno != EACCES)
		return fail("unverified accepted");
	printf("M116_PRECISION_UNVERIFIED_DENIAL_OK record=%llu\n",
	       (unsigned long long)publish.record_id);

	memset(&verify, 0, sizeof(verify));
	verify.size = sizeof(verify);
	verify.operation = AGI_LC_KNOWLEDGE_VERIFY;
	verify.record_id = publish.record_id;
	verify.verification_state = AGI_LC_KNOWLEDGE_VERIFY_VERIFIED;
	memcpy(verify.evidence_digest, publish.evidence_digest,
	       AGI_LC_DIGEST_SIZE);
	verify.correlation = 116105;
	if (ioctl(fd, AGI_LC_KNOWLEDGE, &verify) < 0 ||
	    verify.status != 0 ||
	    verify.verification_state != AGI_LC_KNOWLEDGE_VERIFY_VERIFIED)
		return fail("verify");

	memset(&validate, 0, sizeof(validate));
	validate.size = sizeof(validate);
	validate.operation = AGI_LC_KNOWLEDGE_VALIDATE;
	validate.flags = AGI_LC_KNOWLEDGE_FLAG_FRESHNESS_REQUIRED;
	validate.record_id = publish.record_id;
	validate.confidence_ppm = 900001;
	validate.correlation = 116106;
	if (ioctl(fd, AGI_LC_KNOWLEDGE, &validate) == 0 || errno != EACCES)
		return fail("confidence threshold accepted");
	printf("M116_PRECISION_CONFIDENCE_DENIAL_OK threshold=900001\n");

	memset(&validate, 0, sizeof(validate));
	validate.size = sizeof(validate);
	validate.operation = AGI_LC_KNOWLEDGE_VALIDATE;
	validate.flags = AGI_LC_KNOWLEDGE_FLAG_PRIMARY;
	validate.record_id = publish.record_id;
	validate.confidence_ppm = 900000;
	validate.correlation = 116108;
	if (ioctl(fd, AGI_LC_KNOWLEDGE, &validate) == 0 || errno != EINVAL)
		return fail("malformed flags accepted");
	printf("M116_PRECISION_MALFORMED_DENIAL_OK\n");

	memset(&validate, 0, sizeof(validate));
	validate.size = sizeof(validate);
	validate.operation = AGI_LC_KNOWLEDGE_VALIDATE;
	validate.flags = AGI_LC_KNOWLEDGE_FLAG_FRESHNESS_REQUIRED;
	validate.record_id = publish.record_id;
	validate.confidence_ppm = 900000;
	validate.correlation = 116107;
	if (ioctl(fd, AGI_LC_KNOWLEDGE, &validate) < 0 ||
	    validate.status != 0 ||
	    validate.verification_state != AGI_LC_KNOWLEDGE_VERIFY_VERIFIED ||
	    validate.freshness_state != AGI_LC_KNOWLEDGE_FRESH ||
	    validate.evidence_sequence == 0)
		return fail("fresh verified acceptance");
	printf("M116_PRECISION_FRESH_VERIFIED_OK confidence=%u evidence=%llu\n",
	       validate.confidence_ppm,
	       (unsigned long long)validate.evidence_sequence);
	close(fd);
	printf("M116_PRECISION_SELFTEST_EXIT=0\n");
	return 0;
}
