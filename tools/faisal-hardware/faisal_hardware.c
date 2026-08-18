#include "faisal_hardware.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int digest_path(const struct fhd_path *path,
			uint8_t digest[FHD_DIGEST_SIZE]);

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[FHD_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0U;
	int result = FHD_ERR_TAMPER;

	if ((data == NULL && length != 0U) || digest == NULL)
		return FHD_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return FHD_ERR_TAMPER;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, data, length) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) == 1 &&
	    digest_length == FHD_DIGEST_SIZE)
		result = FHD_STATUS_OK;
	EVP_MD_CTX_free(ctx);
	return result;
}

static int present(const uint8_t digest[FHD_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 0;
	for (i = 0U; i < FHD_DIGEST_SIZE; ++i)
		if (digest[i] != 0U)
			return 1;
	return 0;
}

static int valid_string(const char *value, size_t size)
{
	return value != NULL && value[0] != '\0' && memchr(value, '\0', size) != NULL;
}

static int device_index(const struct fhd_service *service, uint64_t device_id)
{
	size_t i;

	for (i = 0U; i < service->device_count; ++i)
		if (service->devices[i].device_id == device_id)
			return (int)i;
	return -1;
}

static int path_index(const struct fhd_service *service, uint64_t path_id)
{
	size_t i;

	for (i = 0U; i < service->path_count; ++i)
		if (service->paths[i].path_id == path_id)
			return (int)i;
	return -1;
}

static int valid_device(const struct fhd_device *device)
{
	if (device == NULL || device->abi_version != FHD_ABI_VERSION ||
	    device->device_id == 0U || device->generation == 0U ||
	    device->state < FHD_STATE_HEALTHY || device->state > FHD_STATE_QUARANTINED ||
	    device->class_id < FHD_CLASS_CPU || device->class_id > FHD_CLASS_VIRTUAL ||
	    device->isolation_level > FHD_ISOLATION_CONFIDENTIAL ||
	    device->available_memory_bytes > device->total_memory_bytes ||
	    device->available_compute_units > device->total_compute_units ||
	    device->thermal_permille > 1000U ||
	    device->power_now_uw > device->power_budget_uw ||
	    !present(device->identity_digest) || !valid_string(device->name, sizeof(device->name)))
		return FHD_ERR_ARGUMENT;
	return FHD_STATUS_OK;
}

static int valid_path(const struct fhd_path *path)
{
	uint8_t expected[FHD_DIGEST_SIZE];

	if (path == NULL || path->abi_version != FHD_ABI_VERSION || path->path_id == 0U ||
	    path->source_id == 0U || path->destination_id == 0U ||
	    path->source_id == path->destination_id || path->generation == 0U ||
	    path->state < FHD_STATE_HEALTHY || path->state > FHD_STATE_QUARANTINED ||
	    path->transport < FHD_TRANSPORT_SOFTWARE || path->transport > FHD_TRANSPORT_IOMMUFD ||
	    path->isolation_level > FHD_ISOLATION_CONFIDENTIAL || path->bandwidth_mb_s == 0U ||
	    path->latency_ns == 0U || !present(path->path_digest) ||
	    digest_path(path, expected) != FHD_STATUS_OK ||
	    memcmp(expected, path->path_digest, FHD_DIGEST_SIZE) != 0)
		return FHD_ERR_ARGUMENT;
	return FHD_STATUS_OK;
}

static int digest_path(const struct fhd_path *path,
			uint8_t digest[FHD_DIGEST_SIZE])
{
	struct fhd_path copy;

	if (path == NULL)
		return FHD_ERR_ARGUMENT;
	copy = *path;
	memset(copy.path_digest, 0, sizeof(copy.path_digest));
	return digest_bytes(&copy, sizeof(copy), digest);
}

int fhd_compute_path_digest(const struct fhd_path *path,
			    uint8_t digest[FHD_DIGEST_SIZE])
{
	return digest_path(path, digest);
}

static int digest_request(const struct fhd_request *request,
			  uint8_t digest[FHD_DIGEST_SIZE])
{
	return digest_bytes(request, sizeof(*request), digest);
}

static int digest_decision(const struct fhd_decision *decision,
			   uint8_t digest[FHD_DIGEST_SIZE])
{
	struct fhd_decision copy;

	if (decision == NULL)
		return FHD_ERR_ARGUMENT;
	copy = *decision;
	memset(copy.decision_digest, 0, sizeof(copy.decision_digest));
	return digest_bytes(&copy, sizeof(copy), digest);
}

static int device_matches(const struct fhd_service *service,
			  const struct fhd_device *device,
			  const struct fhd_request *request,
			  uint32_t *violations)
{
	if (device->abi_version != FHD_ABI_VERSION)
		*violations |= FHD_VIOLATION_ABI;
	if (device->class_id != request->class_id &&
	    !(request->flags & FHD_REQUEST_ALLOW_FALLBACK && device->class_id == FHD_CLASS_CPU))
		*violations |= FHD_VIOLATION_CLASS;
	if ((device->capabilities & request->required_capabilities) !=
	    request->required_capabilities)
		*violations |= FHD_VIOLATION_CAPABILITY;
	if (device->available_memory_bytes < request->memory_bytes)
		*violations |= FHD_VIOLATION_MEMORY;
	if (device->state != FHD_STATE_HEALTHY)
		*violations |= FHD_VIOLATION_HEALTH;
	if (request->flags & FHD_REQUEST_REQUIRE_ISOLATION) {
		if (device->isolation_level < request->required_isolation)
			*violations |= FHD_VIOLATION_ISOLATION;
	}
	if ((request->flags & FHD_REQUEST_REQUIRE_ATTESTATION) &&
	    (!device->attestation_verified || !device->driver_verified))
		*violations |= FHD_VIOLATION_ATTESTATION;
	if (request->max_power_uw != 0U && device->power_now_uw > request->max_power_uw)
		*violations |= FHD_VIOLATION_POWER;
	if (request->max_thermal_permille != 0U &&
	    device->thermal_permille > request->max_thermal_permille)
		*violations |= FHD_VIOLATION_THERMAL;
	if (device->generation != request->generation || service->generation != request->generation)
		*violations |= FHD_VIOLATION_GENERATION;
	return *violations == 0U ? FHD_STATUS_OK : FHD_ERR_POLICY;
}

static int path_matches(const struct fhd_path *path, const struct fhd_request *request,
			uint64_t destination_id, uint32_t *violations)
{
	if (path->destination_id != destination_id || path->state != FHD_STATE_HEALTHY)
		*violations |= FHD_VIOLATION_PATH;
	if (request->source_device_id != 0U && path->source_id != request->source_device_id)
		*violations |= FHD_VIOLATION_PATH;
	if (path->generation != request->generation)
		*violations |= FHD_VIOLATION_GENERATION;
	{
		const uint64_t path_required = request->required_capabilities &
			(FHD_CAP_DMA | FHD_CAP_PEER_DMA | FHD_CAP_RDMA | FHD_CAP_CXL |
			 FHD_CAP_IOMMU | FHD_CAP_DIRECT_USERSpace);
		if ((path->capabilities & path_required) != path_required)
			*violations |= FHD_VIOLATION_CAPABILITY;
	}
	if (request->min_bandwidth_mb_s != 0U &&
	    path->bandwidth_mb_s < request->min_bandwidth_mb_s)
		*violations |= FHD_VIOLATION_BANDWIDTH;
	if (request->max_latency_ns != 0U && path->latency_ns > request->max_latency_ns)
		*violations |= FHD_VIOLATION_LATENCY;
	if ((request->flags & FHD_REQUEST_REQUIRE_ATTESTATION) && !path->attestation_verified)
		*violations |= FHD_VIOLATION_ATTESTATION;
	return *violations == 0U ? FHD_STATUS_OK : FHD_ERR_POLICY;
}

static uint64_t score_device(const struct fhd_device *device,
			     const struct fhd_request *request, uint32_t fallback)
{
	uint64_t score = device->memory_bandwidth_mb_s / 4U;
	uint64_t thermal_headroom = 1000U - device->thermal_permille;
	uint64_t power_headroom = device->power_budget_uw > device->power_now_uw ?
		device->power_budget_uw - device->power_now_uw : 0U;

	score += thermal_headroom * 100U;
	if (request->flags & FHD_REQUEST_PREFER_BANDWIDTH)
		score += device->memory_bandwidth_mb_s * 8U;
	if (request->flags & FHD_REQUEST_PREFER_LOW_POWER)
		score += power_headroom / 1000U;
	if (request->flags & FHD_REQUEST_PREFER_LOW_LATENCY)
		score += device->available_compute_units * 4U;
	if (!fallback)
		score += 1000000000ULL;
	return score;
}

static int select_locked(struct fhd_service *service,
			 const struct fhd_request *request, struct fhd_decision *out)
{
	struct fhd_decision best;
	uint64_t best_score = 0U;
	int best_index = -1;
	uint32_t best_violations = 0U;
	size_t i;

	if (request == NULL || out == NULL || request->abi_version != FHD_ABI_VERSION ||
	    request->class_id < FHD_CLASS_CPU || request->class_id > FHD_CLASS_VIRTUAL ||
	    request->generation == 0U || request->required_capabilities == 0U ||
	    request->memory_bytes == 0U || request->compute_units == 0U ||
	    request->generation != service->generation)
		return FHD_ERR_ARGUMENT;
	memset(&best, 0, sizeof(best));
	for (i = 0U; i < service->device_count; ++i) {
		struct fhd_device *device = &service->devices[i];
		uint32_t violations = 0U;
		uint32_t fallback = device->class_id != request->class_id;
		uint64_t score;
		size_t p;
		int candidate_path_index = -1;
		int path_found = request->source_device_id == 0U;
		if (device_matches(service, device, request, &violations) != FHD_STATUS_OK)
			continue;
		if (fallback && !(request->flags & FHD_REQUEST_ALLOW_FALLBACK))
			continue;
		for (p = 0U; p < service->path_count; ++p) {
			uint32_t path_violations = 0U;
			if (path_matches(&service->paths[p], request, device->device_id,
					&path_violations) == FHD_STATUS_OK) {
				path_found = 1;
				if (candidate_path_index < 0 || service->paths[p].bandwidth_mb_s >
				    service->paths[candidate_path_index].bandwidth_mb_s)
					candidate_path_index = (int)p;
			}
		}
		if (!path_found)
			continue;
		score = score_device(device, request, fallback);
		if (best_index < 0 || score > best_score ||
		    (score == best_score && device->device_id < best.device_id)) {
			best_score = score;
			best_index = (int)i;
			best_violations = violations;
			best.fallback_used = fallback;
			best.path_id = candidate_path_index >= 0 ? service->paths[candidate_path_index].path_id : 0U;
			best.estimated_bandwidth_mb_s = candidate_path_index >= 0 ?
				service->paths[candidate_path_index].bandwidth_mb_s : device->memory_bandwidth_mb_s;
			best.estimated_latency_ns = candidate_path_index >= 0 ?
				service->paths[candidate_path_index].latency_ns : 0U;
		}
	}
	if (best_index < 0) {
		memset(out, 0, sizeof(*out));
		out->action = FHD_ACTION_REJECT;
		out->violation_mask = FHD_VIOLATION_NO_FALLBACK;
		snprintf(out->reason, sizeof(out->reason), "no_safe_execution_path");
		return FHD_ERR_NO_PATH;
	}
	best.decision_id = service->next_decision_id++;
	best.generation = request->generation;
	best.device_id = service->devices[best_index].device_id;
	best.reserved_memory_bytes = request->memory_bytes;
	best.reserved_compute_units = request->compute_units;
	best.selected_capabilities = service->devices[best_index].capabilities &
		request->required_capabilities;
	best.violation_mask = best_violations;
	best.action = best.fallback_used ? FHD_ACTION_FALLBACK : FHD_ACTION_SELECT;
	snprintf(best.reason, sizeof(best.reason), best.fallback_used ?
		 "cpu_fallback_selected" : "hardware_path_selected");
	if (digest_request(request, best.request_digest) != FHD_STATUS_OK ||
	    digest_decision(&best, best.decision_digest) != FHD_STATUS_OK)
		return FHD_ERR_TAMPER;
	*out = best;
	return FHD_STATUS_OK;
}

int fhd_init(struct fhd_service *service, uint64_t generation)
{
	if (service == NULL || generation == 0U)
		return FHD_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	if (pthread_mutex_init(&service->lock, NULL) != 0)
		return FHD_ERR_CONFLICT;
	service->generation = generation;
	service->next_decision_id = 1U;
	service->next_allocation_id = 1U;
	return FHD_STATUS_OK;
}

void fhd_close(struct fhd_service *service)
{
	if (service != NULL)
		pthread_mutex_destroy(&service->lock);
}

int fhd_add_device(struct fhd_service *service, const struct fhd_device *device)
{
	int result;

	if (service == NULL || valid_device(device) != FHD_STATUS_OK)
		return FHD_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FHD_ERR_CONFLICT;
	if (device->generation != service->generation)
		result = FHD_ERR_GENERATION;
	else if (service->device_count >= FHD_MAX_DEVICES || device_index(service, device->device_id) >= 0)
		result = FHD_ERR_FULL;
	else {
		service->devices[service->device_count++] = *device;
		result = FHD_STATUS_OK;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fhd_update_device(struct fhd_service *service, const struct fhd_device *device)
{
	int index;
	int result;

	if (service == NULL || valid_device(device) != FHD_STATUS_OK)
		return FHD_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FHD_ERR_CONFLICT;
	index = device_index(service, device->device_id);
	if (index < 0)
		result = FHD_ERR_NOT_FOUND;
	else if (device->generation != service->devices[index].generation)
		result = FHD_ERR_GENERATION;
	else {
		service->devices[index] = *device;
		result = FHD_STATUS_OK;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fhd_add_path(struct fhd_service *service, const struct fhd_path *path)
{
	int result;

	if (service == NULL || valid_path(path) != FHD_STATUS_OK)
		return FHD_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FHD_ERR_CONFLICT;
	if (path->generation != service->generation)
		result = FHD_ERR_GENERATION;
	else if (service->path_count >= FHD_MAX_PATHS || path_index(service, path->path_id) >= 0)
		result = FHD_ERR_FULL;
	else {
		service->paths[service->path_count++] = *path;
		result = FHD_STATUS_OK;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fhd_fail_device(struct fhd_service *service, uint64_t device_id,
		    uint64_t generation, uint32_t state)
{
	int index;
	int result;

	if (service == NULL || device_id == 0U || generation == 0U ||
	    state < FHD_STATE_HEALTHY || state > FHD_STATE_QUARANTINED)
		return FHD_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FHD_ERR_CONFLICT;
	index = device_index(service, device_id);
	if (index < 0)
		result = FHD_ERR_NOT_FOUND;
	else if (service->devices[index].generation != generation)
		result = FHD_ERR_GENERATION;
	else {
		service->devices[index].state = state;
		result = FHD_STATUS_OK;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fhd_query_device(const struct fhd_service *service, uint64_t device_id,
		     struct fhd_device *out)
{
	int index;

	if (service == NULL || out == NULL || device_id == 0U)
		return FHD_ERR_ARGUMENT;
	if (pthread_mutex_lock((pthread_mutex_t *)&service->lock) != 0)
		return FHD_ERR_CONFLICT;
	index = device_index(service, device_id);
	if (index < 0) {
		pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
		return FHD_ERR_NOT_FOUND;
	}
	*out = service->devices[index];
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return FHD_STATUS_OK;
}

int fhd_query_path(const struct fhd_service *service, uint64_t path_id,
		  struct fhd_path *out)
{
	int index;

	if (service == NULL || out == NULL || path_id == 0U)
		return FHD_ERR_ARGUMENT;
	if (pthread_mutex_lock((pthread_mutex_t *)&service->lock) != 0)
		return FHD_ERR_CONFLICT;
	index = path_index(service, path_id);
	if (index < 0) {
		pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
		return FHD_ERR_NOT_FOUND;
	}
	*out = service->paths[index];
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return FHD_STATUS_OK;
}

int fhd_select(struct fhd_service *service, const struct fhd_request *request,
	      struct fhd_decision *out)
{
	int result;

	if (service == NULL || request == NULL || out == NULL)
		return FHD_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FHD_ERR_CONFLICT;
	result = select_locked(service, request, out);
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fhd_reserve(struct fhd_service *service, const struct fhd_request *request,
		struct fhd_decision *decision, struct fhd_partition *out)
{
	int index;
	int result;

	if (service == NULL || request == NULL || decision == NULL || out == NULL)
		return FHD_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FHD_ERR_CONFLICT;
	result = select_locked(service, request, decision);
	if (result != FHD_STATUS_OK) {
		pthread_mutex_unlock(&service->lock);
		return result;
	}
	index = device_index(service, decision->device_id);
	if (index < 0 || service->devices[index].available_memory_bytes < request->memory_bytes ||
	    service->devices[index].available_compute_units < request->compute_units) {
		pthread_mutex_unlock(&service->lock);
		return FHD_ERR_PARTITION;
	}
	service->devices[index].available_memory_bytes -= request->memory_bytes;
	service->devices[index].available_compute_units -= request->compute_units;
	memset(out, 0, sizeof(*out));
	out->allocation_id = service->next_allocation_id++;
	out->device_id = decision->device_id;
	out->generation = request->generation;
	out->memory_bytes = request->memory_bytes;
	out->compute_units = request->compute_units;
	out->capabilities = decision->selected_capabilities;
	if (digest_bytes(out, sizeof(*out), out->grant_digest) != FHD_STATUS_OK) {
		service->devices[index].available_memory_bytes += request->memory_bytes;
		service->devices[index].available_compute_units += request->compute_units;
		pthread_mutex_unlock(&service->lock);
		return FHD_ERR_TAMPER;
	}
	decision->action = FHD_ACTION_RESERVE;
	if (digest_decision(decision, decision->decision_digest) != FHD_STATUS_OK) {
		service->devices[index].available_memory_bytes += request->memory_bytes;
		service->devices[index].available_compute_units += request->compute_units;
		pthread_mutex_unlock(&service->lock);
		return FHD_ERR_TAMPER;
	}
	pthread_mutex_unlock(&service->lock);
	return FHD_STATUS_OK;
}

int fhd_release(struct fhd_service *service, const struct fhd_partition *partition)
{
	int index;
	uint8_t digest[FHD_DIGEST_SIZE];
	struct fhd_partition copy;

	if (service == NULL || partition == NULL || partition->allocation_id == 0U ||
	    partition->device_id == 0U || partition->generation == 0U)
		return FHD_ERR_ARGUMENT;
	copy = *partition;
	memset(copy.grant_digest, 0, sizeof(copy.grant_digest));
	if (digest_bytes(&copy, sizeof(copy), digest) != FHD_STATUS_OK ||
	    memcmp(digest, partition->grant_digest, FHD_DIGEST_SIZE) != 0)
		return FHD_ERR_TAMPER;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FHD_ERR_CONFLICT;
	index = device_index(service, partition->device_id);
	if (index < 0)
		return pthread_mutex_unlock(&service->lock), FHD_ERR_NOT_FOUND;
	if (service->devices[index].generation != partition->generation)
		return pthread_mutex_unlock(&service->lock), FHD_ERR_GENERATION;
	if (service->devices[index].available_memory_bytes + partition->memory_bytes >
	    service->devices[index].total_memory_bytes ||
	    service->devices[index].available_compute_units + partition->compute_units >
	    service->devices[index].total_compute_units)
		return pthread_mutex_unlock(&service->lock), FHD_ERR_PARTITION;
	service->devices[index].available_memory_bytes += partition->memory_bytes;
	service->devices[index].available_compute_units += partition->compute_units;
	pthread_mutex_unlock(&service->lock);
	return FHD_STATUS_OK;
}

int fhd_verify_decision(const struct fhd_decision *decision,
			const struct fhd_request *request)
{
	uint8_t request_digest[FHD_DIGEST_SIZE];
	uint8_t decision_digest[FHD_DIGEST_SIZE];

	if (decision == NULL || request == NULL ||
	    digest_request(request, request_digest) != FHD_STATUS_OK ||
	    memcmp(request_digest, decision->request_digest, FHD_DIGEST_SIZE) != 0 ||
	    digest_decision(decision, decision_digest) != FHD_STATUS_OK ||
	    memcmp(decision_digest, decision->decision_digest, FHD_DIGEST_SIZE) != 0)
		return FHD_ERR_TAMPER;
	return FHD_STATUS_OK;
}

static int build_path(char *buffer, size_t size, const char *root, const char *suffix)
{
	int length;

	if (buffer == NULL || size == 0U || root == NULL || suffix == NULL)
		return FHD_ERR_ARGUMENT;
	length = snprintf(buffer, size, "%s/%s", root, suffix);
	return length < 0 || (size_t)length >= size ? FHD_ERR_ARGUMENT : FHD_STATUS_OK;
}

static int count_entries(const char *root, const char *suffix, uint32_t *count)
{
	char path[PATH_MAX];
	DIR *directory;
	struct dirent *entry;
	uint32_t total = 0U;

	if (count == NULL || build_path(path, sizeof(path), root, suffix) != FHD_STATUS_OK)
		return FHD_ERR_ARGUMENT;
	directory = opendir(path);
	if (directory == NULL) {
		if (errno == ENOENT)
			return *count = 0U, FHD_STATUS_OK;
		return FHD_ERR_UNAVAILABLE;
	}
	while ((entry = readdir(directory)) != NULL)
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
			total++;
	closedir(directory);
	*count = total;
	return FHD_STATUS_OK;
}

static int read_memory(const char *proc_root, uint64_t *total, uint64_t *available)
{
	char path[PATH_MAX];
	char line[256];
	FILE *file;
	unsigned long long value;
	int found_total = 0;
	int found_available = 0;

	if (total == NULL || available == NULL || build_path(path, sizeof(path), proc_root, "meminfo") != FHD_STATUS_OK)
		return FHD_ERR_ARGUMENT;
	file = fopen(path, "r");
	if (file == NULL)
		return FHD_ERR_UNAVAILABLE;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (sscanf(line, "MemTotal: %llu kB", &value) == 1) {
			*total = (uint64_t)value * 1024ULL;
			found_total = 1;
		} else if (sscanf(line, "MemAvailable: %llu kB", &value) == 1) {
			*available = (uint64_t)value * 1024ULL;
			found_available = 1;
		}
	}
	fclose(file);
	return found_total && found_available ? FHD_STATUS_OK : FHD_ERR_UNAVAILABLE;
}

static int read_cpu_features(const char *proc_root, uint32_t *online,
			     uint32_t *features)
{
	char path[PATH_MAX];
	char line[512];
	FILE *file;
	uint32_t count = 0U;

	if (online == NULL || features == NULL || build_path(path, sizeof(path), proc_root, "stat") != FHD_STATUS_OK)
		return FHD_ERR_ARGUMENT;
	file = fopen(path, "r");
	if (file == NULL)
		return FHD_ERR_UNAVAILABLE;
	while (fgets(line, sizeof(line), file) != NULL)
		if (strncmp(line, "cpu", 3U) == 0 && isdigit((unsigned char)line[3]))
			count++;
	fclose(file);
	if (count == 0U || build_path(path, sizeof(path), proc_root, "cpuinfo") != FHD_STATUS_OK)
		return FHD_ERR_UNAVAILABLE;
	file = fopen(path, "r");
	if (file == NULL)
		return FHD_ERR_UNAVAILABLE;
	*features = 0U;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strstr(line, "sse2") != NULL)
			*features |= FHD_DISCOVERY_SSE2;
		if (strstr(line, "avx2") != NULL)
			*features |= FHD_DISCOVERY_AVX2;
		if (strstr(line, "avx512") != NULL)
			*features |= FHD_DISCOVERY_AVX512;
		if (strstr(line, "asimd") != NULL || strstr(line, "neon") != NULL)
			*features |= FHD_DISCOVERY_NEON;
		if (strstr(line, "sve") != NULL)
			*features |= FHD_DISCOVERY_SVE;
		if (strstr(line, "sme") != NULL)
			*features |= FHD_DISCOVERY_SME;
	}
	fclose(file);
	*online = count;
	return FHD_STATUS_OK;
}

int fhd_compute_discovery_digest(const struct fhd_discovery_report *report,
				 uint8_t digest[FHD_DIGEST_SIZE])
{
	struct fhd_discovery_report copy;

	if (report == NULL || digest == NULL)
		return FHD_ERR_ARGUMENT;
	copy = *report;
	memset(copy.host_digest, 0, sizeof(copy.host_digest));
	return digest_bytes(&copy, sizeof(copy), digest);
}

int fhd_discover_host(struct fhd_service *service, const char *proc_root,
			      const char *sysfs_root,
			      struct fhd_discovery_report *out)
{
	struct fhd_device cpu;
	uint8_t digest[FHD_DIGEST_SIZE];
	uint32_t vector_features = 0U;
	int result;

	if (service == NULL || proc_root == NULL || sysfs_root == NULL || out == NULL)
		return FHD_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->abi_version = FHD_ABI_VERSION;
	result = read_cpu_features(proc_root, &out->online_cpus, &vector_features);
	if (result != FHD_STATUS_OK || read_memory(proc_root, &out->memory_total_bytes,
						&out->memory_available_bytes) != FHD_STATUS_OK)
		return FHD_ERR_UNAVAILABLE;
	out->vector_features = vector_features;
	if (count_entries(sysfs_root, "class/drm", &out->drm_devices) != FHD_STATUS_OK ||
	    count_entries(sysfs_root, "class/infiniband", &out->rdma_devices) != FHD_STATUS_OK ||
	    count_entries(sysfs_root, "class/nvme", &out->nvme_devices) != FHD_STATUS_OK ||
	    count_entries(sysfs_root, "bus/cxl/devices", &out->cxl_devices) != FHD_STATUS_OK)
		return FHD_ERR_UNAVAILABLE;
	if (count_entries(sysfs_root, "class/power_supply", &out->power_telemetry) != FHD_STATUS_OK ||
	    count_entries(sysfs_root, "class/thermal", &out->thermal_telemetry) != FHD_STATUS_OK)
		return FHD_ERR_UNAVAILABLE;
	out->attestation_observed = access("/dev/tpmrm0", F_OK) == 0 || access("/dev/tpm0", F_OK) == 0;
	if (fhd_compute_discovery_digest(out, digest) != FHD_STATUS_OK)
		return FHD_ERR_TAMPER;
	memcpy(out->host_digest, digest, sizeof(out->host_digest));
	memset(&cpu, 0, sizeof(cpu));
	cpu.abi_version = FHD_ABI_VERSION;
	cpu.class_id = FHD_CLASS_CPU;
	cpu.state = FHD_STATE_HEALTHY;
	cpu.isolation_level = FHD_ISOLATION_PROCESS;
	cpu.device_id = 1U;
	cpu.generation = service->generation;
	cpu.total_memory_bytes = out->memory_total_bytes;
	cpu.available_memory_bytes = out->memory_available_bytes;
	cpu.total_compute_units = out->online_cpus;
	cpu.available_compute_units = out->online_cpus;
	cpu.memory_bandwidth_mb_s = 0U;
	cpu.power_budget_uw = 0U;
	cpu.power_now_uw = 0U;
	cpu.thermal_permille = 0U;
	cpu.driver_verified = 1U;
	cpu.attestation_verified = 0U;
	cpu.capabilities = FHD_CAP_SCALAR | FHD_CAP_ASYNC_IO;
	if (vector_features & (FHD_DISCOVERY_SSE2 | FHD_DISCOVERY_NEON))
		cpu.capabilities |= FHD_CAP_SIMD;
	if (vector_features & (FHD_DISCOVERY_AVX2 | FHD_DISCOVERY_AVX512 |
				       FHD_DISCOVERY_SVE | FHD_DISCOVERY_SME))
		cpu.capabilities |= FHD_CAP_VECTOR;
	if (out->power_telemetry != 0U)
		cpu.capabilities |= FHD_CAP_POWER_TELEMETRY;
	if (out->thermal_telemetry != 0U)
		cpu.capabilities |= FHD_CAP_THERMAL_TELEMETRY;
	memcpy(cpu.identity_digest, out->host_digest, sizeof(cpu.identity_digest));
	snprintf(cpu.name, sizeof(cpu.name), "discovered-host-cpu");
	return fhd_add_device(service, &cpu);
}

int fhd_test_invalid_device_rejection(struct fhd_service *service)
{
	struct fhd_request request;
	struct fhd_decision decision;

	if (service == NULL)
		return FHD_ERR_ARGUMENT;
	memset(&request, 0, sizeof(request));
	request.abi_version = FHD_ABI_VERSION;
	request.class_id = FHD_CLASS_TPU;
	request.flags = FHD_REQUEST_REQUIRE_ISOLATION;
	request.required_isolation = FHD_ISOLATION_CONFIDENTIAL;
	request.generation = service->generation;
	request.required_capabilities = FHD_CAP_TENSOR | FHD_CAP_CONFIDENTIAL;
	request.memory_bytes = 1U;
	request.compute_units = 1U;
	return fhd_select(service, &request, &decision) == FHD_ERR_NO_PATH ?
		FHD_STATUS_OK : FHD_ERR_NO_PATH;
}

int fhd_test_path_tamper_rejection(struct fhd_service *service)
{
	struct fhd_path path;
	uint8_t digest[FHD_DIGEST_SIZE];

	if (service == NULL || fhd_query_path(service, 1U, &path) != FHD_STATUS_OK)
		return FHD_ERR_ARGUMENT;
	path.bandwidth_mb_s++;
	if (fhd_compute_path_digest(&path, digest) != FHD_STATUS_OK)
		return FHD_ERR_TAMPER;
	return memcmp(digest, path.path_digest, FHD_DIGEST_SIZE) == 0 ?
		FHD_ERR_TAMPER : FHD_STATUS_OK;
}
