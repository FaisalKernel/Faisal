#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define COG_DEVICE "/dev/cog_kernel"
#define COG_NAME_MAX 256
#define COG_IOC_MAGIC 0xCF
#define COG_ATOM_CONCEPT 1U
#define COG_ATOM_RELATION 2U
#define COG_ATOM_SENSORIMOTOR 3U

struct cog_learn_args {
	uint32_t type;
	uint32_t reserved;
	uint64_t uuid;
	uint32_t sti_milli;
	uint32_t lti_milli;
	char name[COG_NAME_MAX];
};
struct cog_think_args {
	uint64_t uuid;
	uint32_t type;
	uint32_t sti_milli;
	uint32_t lti_milli;
	uint32_t reserved;
	char name[COG_NAME_MAX];
};
struct cog_focus_args {
	uint64_t uuid;
	uint32_t sti_milli;
	uint32_t reserved;
};
#define COG_LEARN _IOWR(COG_IOC_MAGIC, 0x01, struct cog_learn_args)
#define COG_THINK _IOWR(COG_IOC_MAGIC, 0x02, struct cog_think_args)
#define COG_FOCUS _IOWR(COG_IOC_MAGIC, 0x03, struct cog_focus_args)

static int fail(const char *what)
{
	fprintf(stderr, "COG_FAIL:%s errno=%d (%s)\n", what, errno, strerror(errno));
	return 1;
}

int main(void)
{
	struct cog_learn_args learn;
	struct cog_think_args think;
	struct cog_focus_args focus;
	int fd;
	uint32_t before;

	fd = open(COG_DEVICE, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail("open");
	memset(&learn, 0, sizeof(learn));
	learn.type = COG_ATOM_CONCEPT;
	snprintf(learn.name, sizeof(learn.name), "faisal-cognitive-memory");
	if (ioctl(fd, COG_LEARN, &learn) < 0 || !learn.uuid)
		return fail("learn");
	printf("COG_LEARN_OK uuid=%" PRIu64 " sti_milli=%u lti_milli=%u\n",
	       learn.uuid, learn.sti_milli, learn.lti_milli);

	memset(&think, 0, sizeof(think));
	think.uuid = learn.uuid;
	if (ioctl(fd, COG_THINK, &think) < 0)
		return fail("think");
	before = think.sti_milli;
	if (think.type != COG_ATOM_CONCEPT || strcmp(think.name, learn.name))
		return fail("think contents");
	printf("COG_THINK_OK type=%u sti_milli=%u name=%s\n",
	       think.type, think.sti_milli, think.name);

	memset(&focus, 0, sizeof(focus));
	focus.uuid = learn.uuid;
	if (ioctl(fd, COG_FOCUS, &focus) < 0 || focus.sti_milli < before + 10000U)
		return fail("focus");
	printf("COG_FOCUS_OK sti_milli=%u\n", focus.sti_milli);

	memset(&think, 0, sizeof(think));
	think.uuid = learn.uuid;
	if (ioctl(fd, COG_THINK, &think) < 0 || think.sti_milli != focus.sti_milli)
		return fail("post-focus think");
	printf("COG_POST_FOCUS_THINK_OK sti_milli=%u\n", think.sti_milli);

	if (ioctl(fd, _IO(COG_IOC_MAGIC, 0x7f), 0) != -1 || errno != ENOTTY)
		return fail("malformed ioctl rejection");
	printf("COG_MALFORMED_IOCTL_REJECT_OK\n");
	close(fd);
	printf("COG_TEST_EXIT=0\n");
	return 0;
}
