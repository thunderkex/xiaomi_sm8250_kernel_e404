/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AxDragonite Driver Header
 * Common definitions for AxDragonite kernel performance interface.
 */

#ifndef _AX_DRAGONITE_H
#define _AX_DRAGONITE_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/version.h>

#define AX_MAX_AFFINITY_RULES 32
#define AX_MAX_BOOST_ENTRIES 32
#define AX_DRAGONITE_TAG "ax_dragonite: "

struct ax_boost_entry {
	struct pid *spid;
	pid_t pid;
	int saved_nice;
	int applied_nice;
	int level;
	bool active;
};

extern struct proc_dir_entry *ax_dragonite_dir;
extern struct proc_dir_entry *ax_named_affinity_dir;
extern bool ax_named_affinity_enabled;

/* Permission validator */
static inline bool ax_dragonite_is_authorized(void)
{
	if (capable(CAP_SYS_NICE) || capable(CAP_SYS_ADMIN))
		return true;
	if (uid_eq(current_euid(), GLOBAL_ROOT_UID))
		return true;
	if (from_kuid(&init_user_ns, current_euid()) == 1000) /* AID_SYSTEM */
		return true;
	return false;
}

/* CPUMask parser supporting hex ("0f", "0x0f") and cpulist ("0-3", "0,1,2") */
int ax_parse_cpumask(const char *buf, cpumask_t *mask);

/* Named affinity hook for task fork (wake_up_new_task) and thread rename (PR_SET_NAME) */
void ax_named_thread_affinity_apply(struct task_struct *p);

/* Subsystem init/exit declarations */
int ax_named_thread_affinity_init(void);
void ax_named_thread_affinity_exit(void);

#endif /* _AX_DRAGONITE_H */
