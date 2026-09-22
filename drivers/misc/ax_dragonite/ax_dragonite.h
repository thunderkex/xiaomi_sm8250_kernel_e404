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
#define AX_MAX_BOOST_ENTRIES 128
#define AX_DRAGONITE_TAG "ax_dragonite: "

/*
 * Every boost / swappiness lease auto-expires so a crashed or restarted
 * framework can never leave a task boosted (or vm.swappiness overridden)
 * forever. Userspace must re-acquire to extend a lease longer than this.
 */
#define AX_LEASE_TTL_MS  15000
#define AX_LEASE_REAP_MS 1000

struct ax_boost_entry {
	struct pid *spid;	/* holds a ref: immune to pid-number reuse */
	pid_t pid;		/* number as seen by the writer, display only */
	int saved_nice;		/* nice value before the first acquire */
	int applied_nice;	/* nice value we set (used to detect foreign changes) */
	int level;
	unsigned long expires;	/* jiffies */
	bool active;
};

extern struct proc_dir_entry *ax_dragonite_dir;
extern struct proc_dir_entry *ax_named_affinity_dir;
extern bool ax_named_affinity_enabled;

/* Permission validator */
static inline bool ax_dragonite_is_authorized(void)
{
	/* _noaudit: don't spam SELinux avc logs for every unprivileged probe */
	if (has_capability_noaudit(current, CAP_SYS_NICE) ||
	    has_capability_noaudit(current, CAP_SYS_ADMIN))
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
