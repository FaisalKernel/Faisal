#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fail(const char *what) { fprintf(stderr, "M64_FAIL:%s:%s\n", what, strerror(errno)); return 1; }
static int drain(int fd) { struct agi_lc_record r; return read(fd, &r, sizeof(r)) == sizeof(r) ? 0 : -1; }

int main(void)
{
    int fd, backing;
    struct agi_lc_create create = { .size = sizeof(create) };
    struct agi_lc_light_agent light = { .size = sizeof(light), .role = AGI_LC_LIGHT_AGENT_ROLE_SECURITY, .workload = AGI_LC_WORKLOAD_VERIFICATION, .correlation = 64001 };
    struct agi_lc_agent agent = { .size = sizeof(agent), .correlation = 64002 };
    struct agi_lc_memory_region region = { .size = sizeof(region), .flags = AGI_LC_MEMORY_REGION_WORKING | AGI_LC_MEMORY_REGION_SHARED, .access = AGI_LC_MEMORY_ACCESS_READ | AGI_LC_MEMORY_ACCESS_WRITE, .size_bytes = 16384, .correlation = 64003 };
    struct agi_lc_tensor_policy tensor;
    struct agi_lc_provenance provenance;
    struct agi_lc_capability_grant grant;
    struct agi_lc_capability_check check;
    struct agi_lc_compute_context context;
    struct agi_lc_provenance_binding binding, query;

    fd = open("/dev/agi_lifecycle", O_RDWR);
    if (fd < 0) return fail("open");
    if (ioctl(fd, AGI_LC_CREATE, &create) < 0 || ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
        ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 || !light.agent_id || !light.capability)
        return fail("session and light agent");
    agent.agent_id = light.agent_id;
    if (ioctl(fd, AGI_LC_SET_AGENT, &agent) < 0) return fail("set agent");
    backing = syscall(SYS_memfd_create, "faisal-m64", MFD_ALLOW_SEALING);
    if (backing < 0 || ftruncate(backing, region.size_bytes) < 0) return fail("backing");
    region.backing_fd = backing;
    if (ioctl(fd, AGI_LC_MEMORY_REGION_CREATE, &region) < 0 || drain(fd) < 0) return fail("region");
    memset(&tensor, 0, sizeof(tensor));
    tensor.size = sizeof(tensor); tensor.operation = AGI_LC_TENSOR_POLICY_SET;
    tensor.rank = 1; tensor.element_size = 4; tensor.preferred_numa_node = AGI_LC_TENSOR_NUMA_ANY;
    tensor.tier_mask = AGI_LC_TENSOR_TIER_DDR; tensor.region_id = region.region_id;
    tensor.capability = region.capability; tensor.total_bytes = region.size_bytes; tensor.alignment = 4096;
    tensor.dimensions[0] = 1024; tensor.strides[0] = 4; tensor.correlation = 64004;
    if (ioctl(fd, AGI_LC_TENSOR_POLICY, &tensor) < 0 || drain(fd) < 0) return fail("tensor");
    memset(&provenance, 0, sizeof(provenance));
    provenance.size = sizeof(provenance); provenance.operation = AGI_LC_PROVENANCE_PUBLISH_ACTION;
    provenance.correlation = 64005; provenance.action_digest[0] = 0xa5;
    if (ioctl(fd, AGI_LC_PROVENANCE_PUBLISH, &provenance) < 0 || !provenance.provenance_id || !provenance.action_sequence)
        return fail("publish provenance");
    memset(&grant, 0, sizeof(grant)); grant.size = sizeof(grant); grant.agent_id = light.agent_id;
    grant.agent_capability = light.capability; grant.rights = AGI_LC_CAP_TENSOR_READ;
    grant.scope_kind = AGI_LC_CAP_SCOPE_TENSOR; grant.scope_access = AGI_LC_SCOPE_READ;
    grant.scope_id = region.region_id; grant.scope_capability = region.capability;
    grant.scope_generation = tensor.generation; grant.correlation = 64006;
    if (ioctl(fd, AGI_LC_CAPABILITY_GRANT, &grant) < 0) return fail("scoped tensor grant");
    memset(&check, 0, sizeof(check)); check.size = sizeof(check); check.grant_id = grant.grant_id;
    check.capability = grant.capability; check.agent_id = light.agent_id; check.agent_capability = light.capability;
    check.requested_rights = AGI_LC_CAP_TENSOR_READ; check.scope_kind = grant.scope_kind;
    check.scope_access = grant.scope_access; check.scope_id = grant.scope_id;
    check.scope_capability = grant.scope_capability; check.scope_generation = grant.scope_generation; check.correlation = 64007;
    if (ioctl(fd, AGI_LC_CAPABILITY_CHECK, &check) < 0 || check.status != AGI_LC_CAP_STATUS_ACTIVE || check.allowed_rights != AGI_LC_CAP_TENSOR_READ)
        return fail("scoped tensor check");
    printf("M64_TENSOR_SCOPE_ALLOW_OK\n");
    memset(&check, 0, sizeof(check));
    check.size = sizeof(check); check.grant_id = grant.grant_id;
    check.capability = grant.capability; check.agent_id = light.agent_id;
    check.agent_capability = light.capability ^ 1;
    check.requested_rights = AGI_LC_CAP_TENSOR_READ;
    check.scope_kind = AGI_LC_CAP_SCOPE_TENSOR; check.scope_access = AGI_LC_SCOPE_READ;
    check.scope_id = region.region_id; check.scope_capability = region.capability;
    check.scope_generation = tensor.generation; check.correlation = 64007;
    if (ioctl(fd, AGI_LC_CAPABILITY_CHECK, &check) < 0 || check.status != AGI_LC_CAP_STATUS_DENIED) return fail("cross-agent denial");
    printf("M64_CROSS_AGENT_REJECT_OK\n");
    memset(&binding, 0, sizeof(binding)); binding.size = sizeof(binding); binding.operation = AGI_LC_PROVENANCE_BIND;
    binding.scope_kind = AGI_LC_PROVENANCE_BIND_TENSOR; binding.resource_id = region.region_id;
    binding.resource_capability = region.capability; binding.resource_generation = tensor.generation;
    binding.provenance_id = provenance.provenance_id; binding.provenance_sequence = provenance.action_sequence; binding.correlation = 64008;
    if (ioctl(fd, AGI_LC_PROVENANCE_BINDING, &binding) < 0 || !binding.binding_id) return fail("tensor provenance bind");
    printf("M64_TENSOR_PROVENANCE_BIND_OK id=%llu\n", (unsigned long long)binding.binding_id);
    query = binding; query.operation = AGI_LC_PROVENANCE_BIND_GET; query.provenance_id = 0; query.provenance_sequence = 0; query.binding_generation = 0;
    if (ioctl(fd, AGI_LC_PROVENANCE_BINDING, &query) < 0 || query.provenance_id != provenance.provenance_id || query.provenance_sequence != provenance.action_sequence)
        return fail("tensor provenance query");
    printf("M64_TENSOR_PROVENANCE_QUERY_OK\n");
    memset(&context, 0, sizeof(context)); context.size = sizeof(context); context.operation = AGI_LC_CONTEXT_CREATE;
    context.device_mask = AGI_LC_CONTEXT_DEVICE_CPU; context.correlation = 64009;
    if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &context) < 0 || drain(fd) < 0) return fail("context create");
    memset(&grant, 0, sizeof(grant)); grant.size = sizeof(grant); grant.agent_id = light.agent_id; grant.agent_capability = light.capability;
    grant.rights = AGI_LC_CAP_COMPUTE_EXECUTE; grant.scope_kind = AGI_LC_CAP_SCOPE_CONTEXT; grant.scope_access = AGI_LC_SCOPE_EXECUTE;
    grant.scope_id = context.context_id; grant.scope_capability = context.context_capability; grant.scope_generation = context.generation; grant.correlation = 64010;
    if (ioctl(fd, AGI_LC_CAPABILITY_GRANT, &grant) < 0) return fail("scoped context grant");
    memset(&binding, 0, sizeof(binding)); binding.size = sizeof(binding); binding.operation = AGI_LC_PROVENANCE_BIND;
    binding.scope_kind = AGI_LC_PROVENANCE_BIND_CONTEXT; binding.resource_id = context.context_id; binding.resource_capability = context.context_capability;
    binding.resource_generation = context.generation; binding.provenance_id = provenance.provenance_id; binding.provenance_sequence = provenance.action_sequence; binding.correlation = 64011;
    if (ioctl(fd, AGI_LC_PROVENANCE_BINDING, &binding) < 0 || !binding.binding_id) return fail("context provenance bind");
    printf("M64_CONTEXT_SCOPE_AND_PROVENANCE_OK\nM64_SELFTEST_EXIT=0\n");
    close(backing); close(fd); return 0;
}
