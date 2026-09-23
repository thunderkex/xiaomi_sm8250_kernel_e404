// SPDX-License-Identifier: GPL-2.0
/*
 * AxDragonite Named Thread Affinity Support
 *
 * Exposes:
 *  - /proc/ax_named_thread_affinity/rules: register affinity rules (<comm> <mask>)
 *  - /proc/ax_named_thread_affinity/enabled: runtime toggle switch
 *  - Opportunistic affinity application on wake_up_new_task
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/ratelimit.h>
#include <linux/atomic.h>

#include "ax_dragonite.h"

struct named_affinity_rule {
	char comm[TASK_COMM_LEN];
	cpumask_t mask;
	atomic_long_t applied_count;
	bool active;
};

struct proc_dir_entry *ax_named_affinity_dir;
EXPORT_SYMBOL_GPL(ax_named_affinity_dir);

bool ax_named_affinity_enabled = true;
EXPORT_SYMBOL_GPL(ax_named_affinity_enabled);

static struct named_affinity_rule affinity_rules[AX_MAX_AFFINITY_RULES];
static DEFINE_MUTEX(affinity_mutex);

#define AX_AFFINITY_BATCH_SIZE 32

/* Apply mask to all currently existing threads matching comm */
static unsigned long apply_named_affinity_to_tasks(const char *comm,
						    const cpumask_t *mask)
{
	struct task_struct *g, *t;
	struct task_struct *batch[AX_AFFINITY_BATCH_SIZE];
	int count, i;
	unsigned long total_applied = 0;

	do {
		count = 0;
		rcu_read_lock();
		for_each_process_thread(g, t) {
			if (strncmp(t->comm, comm, TASK_COMM_LEN) == 0 &&
			    !cpumask_equal(&t->cpus_allowed, mask)) {
				get_task_struct(t);
				batch[count++] = t;
				if (count == AX_AFFINITY_BATCH_SIZE)
					break;
			}
		}
		rcu_read_unlock();

		for (i = 0; i < count; i++) {
			set_cpus_allowed_ptr(batch[i], mask);
			put_task_struct(batch[i]);
		}
		total_applied += count;
	} while (count == AX_AFFINITY_BATCH_SIZE);

	return total_applied;
}

/* Named affinity hook called from wake_up_new_task() post-unlock and PR_SET_NAME */
void ax_named_thread_affinity_apply(struct task_struct *p)
{
	int i;

	if (!READ_ONCE(ax_named_affinity_enabled))
		return;

	if (!p || (p->flags & PF_KTHREAD))
		return;

	rcu_read_lock();
	for (i = 0; i < AX_MAX_AFFINITY_RULES; i++) {
		if (smp_load_acquire(&affinity_rules[i].active) &&
		    strncmp(p->comm, affinity_rules[i].comm, TASK_COMM_LEN) == 0) {
			cpumask_t mask;

			cpumask_copy(&mask, &affinity_rules[i].mask);
			if (cpumask_empty(&mask)) {
				rcu_read_unlock();
				return;
			}
			atomic_long_inc(&affinity_rules[i].applied_count);
			rcu_read_unlock();
			set_cpus_allowed_ptr(p, &mask);
			return;
		}
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(ax_named_thread_affinity_apply);

/* -------------------------------------------------------------------------
 * /proc/ax_named_thread_affinity/rules
 * ------------------------------------------------------------------------- */
static ssize_t rules_write(struct file *file, const char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	char kbuf[128];
	char *comm_str, *mask_str, *ptr;
	char target_comm[TASK_COMM_LEN];
	cpumask_t mask;
	int i, free_slot = -1, target_slot = -1;
	size_t len = min(count, sizeof(kbuf) - 1);
	unsigned long applied;
	bool is_delete = false;

	if (!ax_dragonite_is_authorized()) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG
				    "unauthorized affinity rule write from uid %u\n",
				    from_kuid(&init_user_ns, current_euid()));
		return -EPERM;
	}

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	ptr = strim(kbuf);

	/* Expect "<comm> <hex_mask_or_cpulist>" or "!<comm>" */
	comm_str = strsep(&ptr, " \t");
	mask_str = ptr ? strim(ptr) : NULL;

	if (!comm_str || strlen(comm_str) == 0) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "malformed rule input: %s\n", kbuf);
		return -EINVAL;
	}

	if (comm_str[0] == '!') {
		is_delete = true;
		strlcpy(target_comm, comm_str + 1, TASK_COMM_LEN);
	} else {
		strlcpy(target_comm, comm_str, TASK_COMM_LEN);
		if (mask_str && (!strcmp(mask_str, "0") ||
				 !strcasecmp(mask_str, "none") ||
				 !strcasecmp(mask_str, "reset") ||
				 !strcasecmp(mask_str, "del")))
			is_delete = true;
	}

	if (is_delete) {
		mutex_lock(&affinity_mutex);
		for (i = 0; i < AX_MAX_AFFINITY_RULES; i++) {
			if (affinity_rules[i].active &&
			    strncmp(affinity_rules[i].comm, target_comm,
				    TASK_COMM_LEN) == 0) {
				/* Pairs with smp_load_acquire in apply hook */
				smp_store_release(&affinity_rules[i].active,
						  false);
				affinity_rules[i].comm[0] = '\0';
				cpumask_clear(&affinity_rules[i].mask);
				target_slot = i;
				break;
			}
		}
		mutex_unlock(&affinity_mutex);
		if (target_slot == -1)
			return -ENOENT;
		return count;
	}

	if (!mask_str || ax_parse_cpumask(mask_str, &mask) < 0 ||
	    cpumask_empty(&mask)) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "invalid cpumask in rule: %s\n",
				    mask_str ? mask_str : "NULL");
		return -EINVAL;
	}

	mutex_lock(&affinity_mutex);
	for (i = 0; i < AX_MAX_AFFINITY_RULES; i++) {
		if (affinity_rules[i].active &&
		    strncmp(affinity_rules[i].comm, target_comm,
			    TASK_COMM_LEN) == 0) {
			target_slot = i;
			break;
		}
		if (!affinity_rules[i].active && free_slot == -1)
			free_slot = i;
	}

	if (target_slot == -1) {
		target_slot = free_slot;
	} else {
		/*
		 * Editing an already-active slot: unpublish and wait out
		 * existing readers before mutating comm/mask. Without this,
		 * ax_named_thread_affinity_apply() (which only holds
		 * rcu_read_lock(), not affinity_mutex) can observe a comm
		 * string or cpumask that is half old, half new.
		 */
		smp_store_release(&affinity_rules[target_slot].active, false);
		synchronize_rcu();
	}

	if (target_slot != -1) {
		strlcpy(affinity_rules[target_slot].comm, target_comm,
			TASK_COMM_LEN);
		cpumask_copy(&affinity_rules[target_slot].mask, &mask);
		atomic_long_set(&affinity_rules[target_slot].applied_count, 0);
		smp_store_release(&affinity_rules[target_slot].active, true);
	}
	mutex_unlock(&affinity_mutex);

	if (target_slot == -1) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "affinity rules table full\n");
		return -ENOSPC;
	}

	/* Apply immediately to running threads matching this comm */
	applied = apply_named_affinity_to_tasks(target_comm, &mask);
	if (applied) {
		mutex_lock(&affinity_mutex);
		if (affinity_rules[target_slot].active &&
		    strncmp(affinity_rules[target_slot].comm, target_comm,
			    TASK_COMM_LEN) == 0)
			atomic_long_add(applied, &affinity_rules[target_slot].applied_count);
		mutex_unlock(&affinity_mutex);
	}

	return count;
}

static int rules_show(struct seq_file *m, void *v)
{
	int i;
	char mask_str[64];

	mutex_lock(&affinity_mutex);
	seq_printf(m, "# comm mask applied_count\n");
	for (i = 0; i < AX_MAX_AFFINITY_RULES; i++) {
		if (affinity_rules[i].active) {
			cpumap_print_to_pagebuf(false, mask_str, &affinity_rules[i].mask);
			seq_printf(m, "%-16s %s %ld\n",
				   affinity_rules[i].comm,
				   strim(mask_str),
				   atomic_long_read(&affinity_rules[i].applied_count));
		}
	}
	mutex_unlock(&affinity_mutex);
	return 0;
}

static int rules_open(struct inode *inode, struct file *file)
{
	return single_open(file, rules_show, NULL);
}

/* -------------------------------------------------------------------------
 * /proc/ax_named_thread_affinity/enabled
 * ------------------------------------------------------------------------- */
static ssize_t enabled_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	char kbuf[8];
	bool val;
	size_t len = min(count, sizeof(kbuf) - 1);

	if (!ax_dragonite_is_authorized())
		return -EPERM;

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	if (kstrtobool(strim(kbuf), &val) < 0)
		return -EINVAL;

	WRITE_ONCE(ax_named_affinity_enabled, val);
	return count;
}

static int enabled_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", READ_ONCE(ax_named_affinity_enabled) ? 1 : 0);
	return 0;
}

static int enabled_open(struct inode *inode, struct file *file)
{
	return single_open(file, enabled_show, NULL);
}

/* -------------------------------------------------------------------------
 * Procfs Ops definition
 * ------------------------------------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops rules_ops = {
	.proc_open = rules_open,
	.proc_read = seq_read,
	.proc_write = rules_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops enabled_ops = {
	.proc_open = enabled_open,
	.proc_read = seq_read,
	.proc_write = enabled_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#else
static const struct file_operations rules_ops = {
	.owner = THIS_MODULE,
	.open = rules_open,
	.read = seq_read,
	.write = rules_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations enabled_ops = {
	.owner = THIS_MODULE,
	.open = enabled_open,
	.read = seq_read,
	.write = enabled_write,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

/* -------------------------------------------------------------------------
 * Init / Exit
 * ------------------------------------------------------------------------- */
/*
 * Named thread affinity is intentionally kept at /proc root to preserve compatibility
 * with Android userspace paths (/proc/ax_named_thread_affinity/{rules,enabled}).
 */
int ax_named_thread_affinity_init(void)
{
	struct proc_dir_entry *entry;

	ax_named_affinity_dir = proc_mkdir("ax_named_thread_affinity", NULL);
	if (!ax_named_affinity_dir) {
		pr_err(AX_DRAGONITE_TAG "failed to create /proc/ax_named_thread_affinity\n");
		return -ENOMEM;
	}

	entry = proc_create("rules", 0640, ax_named_affinity_dir, &rules_ops);
	if (!entry)
		goto err_rules;

	entry = proc_create("enabled", 0640, ax_named_affinity_dir,
			    &enabled_ops);
	if (!entry)
		goto err_enabled;

	/* Compatibility node at /proc/ax_named_thread_affinity_rules */
	entry = proc_create("ax_named_thread_affinity_rules", 0640, NULL,
			    &rules_ops);
	if (!entry)
		goto err_compat;

	return 0;

err_compat:
	remove_proc_entry("enabled", ax_named_affinity_dir);
err_enabled:
	remove_proc_entry("rules", ax_named_affinity_dir);
err_rules:
	remove_proc_entry("ax_named_thread_affinity", NULL);
	ax_named_affinity_dir = NULL;
	return -ENOMEM;
}

void ax_named_thread_affinity_exit(void)
{
	remove_proc_entry("ax_named_thread_affinity_rules", NULL);

	if (ax_named_affinity_dir) {
		remove_proc_entry("enabled", ax_named_affinity_dir);
		remove_proc_entry("rules", ax_named_affinity_dir);
		remove_proc_entry("ax_named_thread_affinity", NULL);
	}
}
