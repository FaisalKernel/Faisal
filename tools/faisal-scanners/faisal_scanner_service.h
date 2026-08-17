#ifndef FAISAL_SCANNER_SERVICE_H
#define FAISAL_SCANNER_SERVICE_H
#include <stddef.h>
#include <stdint.h>
#define FAS_MAX_OUTPUT 8192U
#define FAS_MAX_SUMMARY 256U
#define FAS_DIGEST_SIZE 32U
enum fas_kind { FAS_BUILD=1, FAS_DEPENDENCY=2, FAS_VULNERABILITY=3 };
enum fas_status { FAS_PASS=0, FAS_FAIL=1, FAS_UNAVAILABLE=2, FAS_ARGUMENT=-1, FAS_IO=-2, FAS_LIMIT=-3 };
struct fas_result { uint32_t kind,status; int32_t exit_code; uint64_t observed_bytes,observed_files; uint8_t evidence_digest[FAS_DIGEST_SIZE]; char summary[FAS_MAX_SUMMARY]; };
int fas_scan_build(const char *root, const char *const argv[], size_t argc, struct fas_result *out);
int fas_scan_dependencies(const char *root, struct fas_result *out);
int fas_scan_vulnerabilities(const char *root, struct fas_result *out);
#endif
