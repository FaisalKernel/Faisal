/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AGI_LIFECYCLE_H
#define _LINUX_AGI_LIFECYCLE_H

#include <linux/types.h>

#ifdef CONFIG_AGI_LIFECYCLE_RV_BRIDGE
void agi_lc_rv_report(const char *monitor_name, s32 status);
#else
static inline void agi_lc_rv_report(const char *monitor_name, s32 status)
{
}
#endif

#endif /* _LINUX_AGI_LIFECYCLE_H */
