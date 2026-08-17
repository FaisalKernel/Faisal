#define _GNU_SOURCE
#include "../../faisal-scanners/faisal_scanner_service.h"
#include "../../faisal-engineering/faisal_engineering_service.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void fail(const char *name, int rc)
{
	fprintf(stderr, "M114_SCANNER_FAIL %s rc=%d errno=%d\n", name, rc, errno);
	exit(1);
}

int main(void)
{
	char root[] = "/tmp/faisal-scanners-XXXXXX";
	char manifest[512];
	struct fas_result result;
	struct fen_service engineering;
	struct fen_repo repo;
	struct fen_change change;
	uint8_t digest[FEN_DIGEST_SIZE] = { 0x11 };
	char journal[] = "/tmp/faisal-scanner-gate-XXXXXX";
	int journal_fd;
	const char *const build_argv[] = { "sh", "-c", "printf build-ok", NULL };
	const char manifest_data[] = "{\"dependencies\":{\"example\":\"1.0.0\"}}\n";
	int fd;
	if (!mkdtemp(root))
		fail("MKDTEMP", FAS_IO);
	(void)snprintf(manifest, sizeof(manifest), "%s/package.json", root);
	fd = open(manifest, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || write(fd, manifest_data, sizeof(manifest_data) - 1) !=
	    (ssize_t)(sizeof(manifest_data) - 1))
		fail("MANIFEST", FAS_IO);
	close(fd);
	if (fas_scan_build(root, build_argv, 3, &result) != FAS_PASS ||
	    result.kind != FAS_BUILD || result.status != FAS_PASS || result.exit_code != 0)
		fail("BUILD", FAS_FAIL);
	printf("M114_REAL_BUILD_ADAPTER_OK bytes=%llu\n",
	       (unsigned long long)result.observed_bytes);
	if (fas_scan_dependencies(root, &result) != FAS_PASS ||
	    result.kind != FAS_DEPENDENCY || result.status != FAS_PASS ||
	    result.observed_files != 1 || result.observed_bytes == 0)
		fail("DEPENDENCY", FAS_FAIL);
	printf("M114_REAL_DEPENDENCY_ADAPTER_OK manifests=%llu bytes=%llu\n",
	       (unsigned long long)result.observed_files,
	       (unsigned long long)result.observed_bytes);
	if (fas_scan_vulnerabilities(root, &result) != FAS_PASS ||
	    result.kind != FAS_VULNERABILITY || result.status != FAS_UNAVAILABLE)
		fail("VULNERABILITY_FAIL_CLOSED", FAS_FAIL);
	printf("M114_VULNERABILITY_ADAPTER_FAIL_CLOSED_OK\n");
	journal_fd = mkstemp(journal);
	if (journal_fd < 0)
		fail("GATE_TMP", FAS_IO);
	close(journal_fd);
	unlink(journal);
	if (fen_open(&engineering, journal) != FEN_OK ||
	    fen_register_repo(&engineering, 1, "scanner-fixture", digest, &repo) != FEN_OK ||
	    fen_propose_change(&engineering, repo.repo_id, 7, "scanner evidence", digest,
			       digest, 0, &change) != FEN_OK)
		fail("GATE_OPEN", FAS_FAIL);
	if (fen_record_check(&engineering, change.change_id, FEN_BUILD,
			     result.status == FAS_UNAVAILABLE ? 1 : 0,
			     result.evidence_digest, result.summary, &change) != FEN_OK)
		fail("GATE_BUILD", FAS_FAIL);
	if (fen_record_check(&engineering, change.change_id, FEN_DEPENDENCY, 0,
			     result.evidence_digest, "dependency adapter passed", &change) != FEN_OK)
		fail("GATE_DEPENDENCY", FAS_FAIL);
	if (fen_record_check(&engineering, change.change_id, FEN_VULNERABILITY, 1,
			     result.evidence_digest, "scanner unavailable", &change) != FEN_OK)
		fail("GATE_VULNERABILITY", FAS_FAIL);
	if (fen_verify_change(&engineering, change.change_id, 99, &change) != FEN_ERR_POLICY)
		fail("GATE_FAIL_CLOSED", FAS_FAIL);
	printf("M114_EVIDENCE_GATE_BLOCKS_UNAVAILABLE_SCANNER_OK\n");
	fen_close(&engineering);
	unlink(journal);
	unlink(manifest);
	rmdir(root);
	printf("M114_SCANNER_SELFTEST_EXIT=0\n");
	return 0;
}
