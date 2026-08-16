// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rv.h>

static void faisal_rv_bridge_fixture_react(const char *msg, va_list args)
{
}

static int __init faisal_rv_bridge_fixture_init(void)
{
	static struct rv_monitor fixture = {
		.name = "stall",
		.description = "M88 test-only RV reactor stimulus",
		.enabled = true,
		.react = faisal_rv_bridge_fixture_react,
	};

	rv_react(&fixture, "M88 test-only upstream RV violation\n");
	return 0;
}

static void __exit faisal_rv_bridge_fixture_exit(void)
{
}

module_init(faisal_rv_bridge_fixture_init);
module_exit(faisal_rv_bridge_fixture_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FAISAL M88 test-only RV bridge fixture");
