// SPDX-License-Identifier: GPL-2.0
/*
 * AxDragonite Named Thread Affinity Support
 *
 * Exposes:
 *  - /proc/ax_named_thread_affinity/rules: register affinity rules (<comm> <mask>)
 *  - /proc/ax_named_thread_affinity/enabled: runtime toggle switch
 *  - Affinity applied at PR_SET_NAME (thread names itself) and, as a
 *    fallback for inherited comms, right after wake_up_new_task() drops
 *    its rq/pi locks. It must NEVER be called from a wakeup path
 *    (ttwu_do_wakeup): that runs under rq->lock with IRQs off.
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
#include <linux/rcupdate.h>
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

/* Apply mask to already-running user threads matching comm (single bounded pass) */
#define AX_AFFINITY_BATCH 128

static void apply_named_affinity_to_tasks(const char *comm, const cpumask_t *mask)
{
	struct task_struct *g, *t;
	struct task_struct *batch[AX_AFFINITY_BATCH];
	int i, n = 0;
	bool truncated = false;

	/*
	 * Collect (with references) under RCU, act after rcu_read_unlock():
	 * set_cpus_allowed_ptr() can sleep, and unlocking mid-walk would leave
	 * the iterator on a task that may already be freed. Threads beyond the
	 * batch (or created later) still get the rule via PR_SET_NAME.
	 */
	rcu_read_lock();
	for_each_process_thread(g, t) {
		if ((t->flags & PF_KTHREAD) ||
		    strncmp(t->comm, comm, TASK_COMM_LEN) != 0)
			continue;
		if (n == AX_AFFINITY_BATCH) {
			truncated = true;
			break;
		}
		get_task_struct(t);
		batch[n++] = t;
	}
	rcu_read_unlock();

	for (i = 0; i < n; i++) {
		set_cpus_allowed_ptr(batch[i], mask);
		put_task_struct(batch[i]);
	}

	if (truncated)
		pr_warn_ratelimited(AX_DRAGONITE_TAG
				    "affinity rule '%s': >%d live threads, remainder applied on rename only\n",
				    comm, AX_AFFINITY_BATCH);
}

/*
 * Named affinity hook: PR_SET_NAME (p == current) and wake_up_new_task()
 * (caller holds a reference on p, taken while the rq lock was still held).
 * Runs in preemptible process context, so set_cpus_allowed_ptr() may sleep.
 */
void ax_named_thread_affinity_apply(struct task_struct *p)
{
	cpumask_t mask;
	bool hit = false;
	int i;

	if (!READ_ONCE(ax_named_affinity_enabled))
		return;

	if (!p || (p->flags & PF_KTHREAD))
		return;

	/*
	 * The mask is copied while still inside the RCU section: rules_write()
	 * calls synchronize_rcu() before it edits a live slot, so we can never
	 * observe a half-rewritten comm/mask pair.
	 */
	rcu_read_lock();
	for (i = 0; i < AX_MAX_AFFINITY_RULES; i++) {
		if (smp_load_acquire(&affinity_rules[i].active) &&
		    strncmp(p->comm, affinity_rules[i].comm, TASK_COMM_LEN) == 0) {
			cpumask_copy(&mask, &affinity_rules[i].mask);
			atomic_long_inc(&affinity_rules[i].applied_count);
			hit = true;
			break;
		}
	}
	rcu_read_unlock();

	if (hit && !cpumask_empty(&mask))
		set_cpus_allowed_ptr(p, &mask);
}
EXPORT_SYMBOL_GPL(ax_named_thread_affinity_apply);

/* -------------------------------------------------------------------------
 * /proc/ax_named_thread_affinity/rules
 *
 * Write "<comm> <hexmask|cpulist>" to add/replace a rule, or "<comm> -" to
 * remove it (removal does not restore affinity of threads already pinned).
 * ------------------------------------------------------------------------- */
static ssize_t rules_write(struct file *file, const char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	char kbuf[128];
	char comm[TASK_COMM_LEN];
	char *comm_str, *mask_str, *ptr;
	cpumask_t mask;
	bool remove;
	int i, free_slot = -1, target_slot = -1;
	size_t len = min(count, sizeof(kbuf) - 1);

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

	comm_str = strsep(&ptr, " \t");
	mask_str = ptr ? strim(ptr) : NULL;

	if (!comm_str || !mask_str || strlen(comm_str) == 0 || *mask_str == '\0') {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "malformed rule input: %s\n", kbuf);
		return -EINVAL;
	}

	/*
	 * Task names are truncated to TASK_COMM_LEN-1 by the kernel. Truncate
	 * the rule the same way, otherwise a >15 char name never matches any
	 * thread and every rewrite of it burns a fresh table slot.
	 */
	strlcpy(comm, comm_str, sizeof(comm));

	remove = !strcmp(mask_str, "-");
	if (!remove &&
	    (ax_parse_cpumask(mask_str, &mask) < 0 || cpumask_empty(&mask))) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "invalid cpumask in rule: %s\n", mask_str);
		return -EINVAL;
	}

	mutex_lock(&affinity_mutex);
	for (i = 0; i < AX_MAX_AFFINITY_RULES; i++) {
		if (affinity_rules[i].active &&
		    strncmp(affinity_rules[i].comm, comm, TASK_COMM_LEN) == 0) {
			target_slot = i;
			break;
		}
		if (!affinity_rules[i].active && free_slot == -1)
			free_slot = i;
	}

	if (remove) {
		if (target_slot == -1) {
			mutex_unlock(&affinity_mutex);
			return -ENOENT;
		}
		smp_store_release(&affinity_rules[target_slot].active, false);
		mutex_unlock(&affinity_mutex);
		return count;
	}

	if (target_slot != -1) {
		/*
		 * Editing a live slot: unpublish and wait out readers first,
		 * otherwise a CPU in ax_named_thread_affinity_apply() can read
		 * a comm/mask pair that is half old, half new.
		 */
		smp_store_release(&affinity_rules[target_slot].active, false);
		synchronize_rcu();
	} else {
		target_slot = free_slot;
	}

	if (target_slot != -1) {
		strlcpy(affinity_rules[target_slot].comm, comm, TASK_COMM_LEN);
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
	apply_named_affinity_to_tasks(comm, &mask);

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
	ax_named_affinity_dir = proc_mkdir("ax_named_thread_affinity", NULL);
	if (!ax_named_affinity_dir) {
		pr_err(AX_DRAGONITE_TAG "failed to create /proc/ax_named_thread_affinity\n");
		return -ENOMEM;
	}

	proc_create("rules", 0640, ax_named_affinity_dir, &rules_ops);
	proc_create("enabled", 0640, ax_named_affinity_dir, &enabled_ops);

	/* Compatibility node at /proc/ax_named_thread_affinity_rules */
	proc_create("ax_named_thread_affinity_rules", 0640, NULL, &rules_ops);

	return 0;
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
