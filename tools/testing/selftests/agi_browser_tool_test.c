#define _GNU_SOURCE
#include "../../faisal-browser/faisal_browser_tool_service.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M75_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void base_action(struct fbt_action_request *request, uint32_t kind)
{
	memset(request, 0, sizeof(*request));
	request->kind = kind;
	request->flags = AGI_LC_BROWSER_FLAG_SEMANTIC;
	request->page_id = 11;
	request->locator_hash = 22;
	request->input_hash = 33;
	request->observation_hash = 44;
	request->result_hash = 55;
}

int main(void)
{
	const char *journal = "/tmp/faisal-m75-browser.journal";
	struct fbt_service service;
	struct fbt_action_request request;
	struct fbt_action_result result;
	struct agi_lc_browser_session browser;
	unsigned int i;
	int rc;

	unlink(journal);
	unlink("/tmp/faisal-m75-browser.journal.ckpt");
	memset(&service, 0, sizeof(service));
	rc = fbt_open(&service, journal);
	if (rc != 0 || service.network.state != AGI_LC_NET_POLICY_STATE_ACTIVE ||
	    !(service.grant.rights & AGI_LC_CAP_BROWSER_CONTROL))
		return fail("scoped kernel setup", rc);
	printf("M75_SCOPED_NETWORK_AND_GRANT_OK policy=%llu grant=%llu\n",
	       (unsigned long long)service.network.policy_id,
	       (unsigned long long)service.grant.grant_id);
	if (fbt_browser_open(&service) != 0)
		return fail("browser open", rc);
	printf("M75_BROWSER_OPEN_OK session=%llu\n",
	       (unsigned long long)service.browser.session_id);
	if (fbt_test_scope_denials(&service) != 0)
		return fail("scope denials", rc);
	printf("M75_SCOPE_DENIALS_OK\n");
	if (fbt_test_hostile_content(&service) != 0)
		return fail("hostile content", rc);
	printf("M75_PROMPT_INJECTION_RESISTANCE_OK\n");
	for (i = 0; i < 64; i++) {
		base_action(&request, AGI_LC_BROWSER_KIND_VERIFY + 1);
		request.reserved = i + 1;
		if (fbt_action(&service, &request, &result) == 0 ||
		    result.decision != FBT_SCOPE_DENIED)
			return fail("malformed action accepted", (int)i);
	}
	printf("M75_ACTION_FUZZ_REJECT_OK iterations=64\n");
	base_action(&request, AGI_LC_BROWSER_KIND_NAVIGATE);
	strncpy(request.url, "https://example.test", sizeof(request.url) - 1);
	strncpy(request.content, "safe navigation observation", sizeof(request.content) - 1);
	if (fbt_action(&service, &request, &result) != 0 ||
	    result.decision != FBT_ALLOWED || !result.action_id ||
	    !result.event_sequence || !result.memory_capability)
		return fail("semantic navigation", rc);
	printf("M75_SEMANTIC_NAVIGATION_OK action=%llu sequence=%llu\n",
	       (unsigned long long)result.action_id,
	       (unsigned long long)result.event_sequence);
	base_action(&request, AGI_LC_BROWSER_KIND_UPLOAD);
	strncpy(request.scope, "safe-upload", sizeof(request.scope) - 1);
	request.operator_confirmed = 1;
	strncpy(request.content, "upload verified fixture", sizeof(request.content) - 1);
	if (fbt_action(&service, &request, &result) != 0 ||
	    result.decision != FBT_ALLOWED)
		return fail("scoped upload", rc);
	printf("M75_UPLOAD_SCOPE_OK\n");
	base_action(&request, AGI_LC_BROWSER_KIND_DOWNLOAD);
	strncpy(request.scope, "safe-download", sizeof(request.scope) - 1);
	request.operator_confirmed = 1;
	strncpy(request.content, "download verified fixture", sizeof(request.content) - 1);
	if (fbt_action(&service, &request, &result) != 0 ||
	    result.decision != FBT_ALLOWED)
		return fail("scoped download", rc);
	printf("M75_DOWNLOAD_SCOPE_OK\n");
	if (fbt_query(&service, &browser) != 0 ||
	    browser.state != AGI_LC_BROWSER_STATE_OPEN || browser.action_count != 3)
		return fail("browser query", rc);
	printf("M75_BROWSER_QUERY_OK actions=%llu semantic=%llu\n",
	       (unsigned long long)browser.action_count,
	       (unsigned long long)browser.semantic_count);
	if (fbt_browser_cancel(&service) != 0 ||
	    fbt_query(&service, &browser) != 0 ||
	    browser.state != AGI_LC_BROWSER_STATE_CANCELLED)
		return fail("browser cancellation", rc);
	printf("M75_BROWSER_CANCEL_OK\n");
	base_action(&request, AGI_LC_BROWSER_KIND_CLICK);
	if (fbt_action(&service, &request, &result) == 0)
		return fail("action after cancellation accepted", rc);
	printf("M75_POST_CANCEL_DENIAL_OK\n");
	fbt_close(&service);
	unlink(journal);
	unlink("/tmp/faisal-m75-browser.journal.ckpt");
	printf("M75_SELFTEST_EXIT=0\n");
	return 0;
}
