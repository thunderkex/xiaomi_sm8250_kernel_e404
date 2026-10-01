// SPDX-License-Identifier: GPL-2.0
/*
 * AxDragonite Named Thread Affinity Support
 *
 * Exposes (official AxDragonite protocol):
 *  - /proc/ax_named_thread_affinity/pid (0666): get/set stored target pid
 *  - /proc/ax_named_thread_affinity/named_thread_affinity (0222):
 *      write "<comm> <mask>" (applies to stored pid)
 *      or "<pid> <comm> <mask>" (explicit pid, also updates stored pid)
 *  - /proc/ax_named_thread_affinity/reset (0222):
 *      reset affinity of stored pid (or write "<pid>" to reset explicit pid)
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
#include <linux/version.h>

#include "ax_dragonite.h"

struct named_affinity_rule {
	char comm[TASK_COMM_LEN];
	cpumask_t mask;
	unsigned long applied_count;
	bool active;
};

struct proc_dir_entry *ax_named_affinity_dir;
EXPORT_SYMBOL_GPL(ax_named_affinity_dir);

bool ax_named_affinity_enabled = true;
EXPORT_SYMBOL_GPL(ax_named_affinity_enabled);

/* Counters exported to stats node in ax_dragonite_core.c */
extern unsigned long ax_total_affinity_applies;
extern unsigned long ax_total_affinity_resets;

/* Stored target pid for two-step write protocol */
static pid_t stored_target_pid;
static DEFINE_SPINLOCK(stored_pid_lock);

static struct named_affinity_rule affinity_rules[AX_MAX_AFFINITY_RULES];
static DEFINE_MUTEX(affinity_mutex);

#define AX_AFFINITY_BATCH_SIZE 32
#define AX_AFFINITY_MAX_ITERS 64

/* Apply mask to all currently existing threads matching comm */
static unsigned long apply_named_affinity_to_tasks(const char *comm,
						    const cpumask_t *mask)
{
	struct task_struct *g, *t;
	struct task_struct *batch[AX_AFFINITY_BATCH_SIZE];
	int count, i;
	int iters = 0;
	unsigned long total_applied = 0;

	do {
		count = 0;
		rcu_read_lock();
		for_each_process_thread(g, t) {
			char comm_buf[TASK_COMM_LEN];

			get_task_comm(comm_buf, t);
			if (strncmp(comm_buf, comm, TASK_COMM_LEN) == 0 &&
			    !cpumask_equal(&t->cpus_allowed, mask)) {
				get_task_struct(t);
				batch[count++] = t;
				if (count == AX_AFFINITY_BATCH_SIZE)
					break;
			}
		}
		rcu_read_unlock();

		for (i = 0; i < count; i++) {
			int ret = set_cpus_allowed_ptr(batch[i], mask);

			if (ret)
				pr_warn_ratelimited(AX_DRAGONITE_TAG
					"affinity apply failed for %s (pid %d): %d\n",
					comm, batch[i]->pid, ret);
			put_task_struct(batch[i]);
		}
		total_applied += count;
	} while (count == AX_AFFINITY_BATCH_SIZE &&
		 ++iters < AX_AFFINITY_MAX_ITERS);

	return total_applied;
}

/* Named affinity hook called from wake_up_new_task() post-unlock and PR_SET_NAME */
void ax_named_thread_affinity_apply(struct task_struct *p)
{
	char comm_buf[TASK_COMM_LEN];
	int i;

	if (!READ_ONCE(ax_named_affinity_enabled))
		return;

	if (!p || (p->flags & PF_KTHREAD))
		return;

	get_task_comm(comm_buf, p);

	rcu_read_lock();
	for (i = 0; i < AX_MAX_AFFINITY_RULES; i++) {
		if (smp_load_acquire(&affinity_rules[i].active) &&
		    strncmp(comm_buf, affinity_rules[i].comm, TASK_COMM_LEN) == 0) {
			cpumask_t mask;

			cpumask_copy(&mask, &affinity_rules[i].mask);
			if (cpumask_empty(&mask)) {
				rcu_read_unlock();
				return;
			}
			affinity_rules[i].applied_count++;
			rcu_read_unlock();
			set_cpus_allowed_ptr(p, &mask);
			return;
		}
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(ax_named_thread_affinity_apply);

/* -------------------------------------------------------------------------
 * Helper: apply mask to all threads matching comm, update stored rule
 * ------------------------------------------------------------------------- */
static int nta_store_rule(const char *target_comm, const cpumask_t *mask)
{
	int i, free_slot = -1, target_slot = -1;
	unsigned long applied;

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

	if (target_slot == -1)
		target_slot = free_slot;

	if (target_slot == -1) {
		mutex_unlock(&affinity_mutex);
		pr_warn_ratelimited(AX_DRAGONITE_TAG "affinity rules table full\n");
		return -ENOSPC;
	}

	strlcpy(affinity_rules[target_slot].comm, target_comm, TASK_COMM_LEN);
	cpumask_copy(&affinity_rules[target_slot].mask, mask);
	smp_store_release(&affinity_rules[target_slot].active, true);
	mutex_unlock(&affinity_mutex);

	applied = apply_named_affinity_to_tasks(target_comm, mask);
	if (applied) {
		WRITE_ONCE(ax_total_affinity_applies,
			   READ_ONCE(ax_total_affinity_applies) + applied);
		mutex_lock(&affinity_mutex);
		if (affinity_rules[target_slot].active &&
		    strncmp(affinity_rules[target_slot].comm, target_comm,
			    TASK_COMM_LEN) == 0)
			affinity_rules[target_slot].applied_count += applied;
		mutex_unlock(&affinity_mutex);
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * /proc/ax_named_thread_affinity/pid  (0666)
 * Read: stored target pid. Write: set stored target pid.
 * ------------------------------------------------------------------------- */
static ssize_t nta_pid_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	char kbuf[16];
	pid_t pid;
	unsigned long flags;
	size_t len = min(count, sizeof(kbuf) - 1);

	if (!ax_dragonite_is_authorized())
		return -EPERM;

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	if (kstrtoint(strim(kbuf), 10, &pid) < 0 || pid < 0)
		return -EINVAL;

	spin_lock_irqsave(&stored_pid_lock, flags);
	stored_target_pid = pid;
	spin_unlock_irqrestore(&stored_pid_lock, flags);

	return count;
}

static int nta_pid_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	pid_t pid;

	spin_lock_irqsave(&stored_pid_lock, flags);
	pid = stored_target_pid;
	spin_unlock_irqrestore(&stored_pid_lock, flags);

	seq_printf(m, "%d\n", pid);
	return 0;
}

static int nta_pid_open(struct inode *inode, struct file *file)
{
	return single_open(file, nta_pid_show, NULL);
}

/* -------------------------------------------------------------------------
 * /proc/ax_named_thread_affinity/named_thread_affinity  (0222)
 * Write "<comm> <mask>" — applies to stored pid's process group by comm name.
 * Write "<pid> <comm> <mask>" — explicit pid, also updates stored pid.
 * The rule is stored for future threads via wake_up_new_task hook.
 * ------------------------------------------------------------------------- */
static ssize_t nta_write(struct file *file, const char __user *ubuf,
			 size_t count, loff_t *ppos)
{
	char kbuf[128];
	char *ptr, *tok;
	char target_comm[TASK_COMM_LEN];
	cpumask_t mask;
	pid_t explicit_pid = 0;
	unsigned long flags;
	size_t len = min(count, sizeof(kbuf) - 1);
	int ret;

	if (!ax_dragonite_is_authorized()) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG
				    "unauthorized named_thread_affinity write from uid %u\n",
				    from_kuid(&init_user_ns, current_euid()));
		return -EPERM;
	}

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	ptr = strim(kbuf);

	/*
	 * Disambiguate "<comm> <mask>" vs "<pid> <comm> <mask>":
	 * If the first token is a pure decimal integer, treat as explicit pid.
	 */
	tok = strsep(&ptr, " \t");
	if (!tok || !*tok)
		return -EINVAL;

	if (ptr) {
		int maybe_pid;

		if (kstrtoint(tok, 10, &maybe_pid) == 0 && maybe_pid > 0) {
			/* Three-token form: <pid> <comm> <mask> */
			explicit_pid = (pid_t)maybe_pid;
			ptr = skip_spaces(ptr);
			tok = strsep(&ptr, " \t");
			if (!tok || !*tok)
				return -EINVAL;
		}
	}

	strlcpy(target_comm, tok, TASK_COMM_LEN);

	if (!ptr || !*ptr) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG
				    "named_thread_affinity: missing mask\n");
		return -EINVAL;
	}
	ptr = skip_spaces(ptr);

	if (ax_parse_cpumask(ptr, &mask) < 0 || cpumask_empty(&mask)) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG
				    "named_thread_affinity: invalid mask: %s\n", ptr);
		return -EINVAL;
	}

	if (explicit_pid) {
		spin_lock_irqsave(&stored_pid_lock, flags);
		stored_target_pid = explicit_pid;
		spin_unlock_irqrestore(&stored_pid_lock, flags);
	}

	ret = nta_store_rule(target_comm, &mask);
	return ret ? ret : (ssize_t)count;
}

/* -------------------------------------------------------------------------
 * /proc/ax_named_thread_affinity/reset  (0222)
 * Write "" or "0" — reset affinity of stored pid's threads matching stored rules.
 * Write "<pid>" — reset affinity of that pid's threads.
 * ------------------------------------------------------------------------- */
static ssize_t nta_reset_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	char kbuf[16];
	pid_t target_pid;
	unsigned long flags;
	struct task_struct *task;
	size_t len = min(count, sizeof(kbuf) - 1);
	int maybe_pid;

	if (!ax_dragonite_is_authorized()) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG
				    "unauthorized reset write from uid %u\n",
				    from_kuid(&init_user_ns, current_euid()));
		return -EPERM;
	}

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	if (kstrtoint(strim(kbuf), 10, &maybe_pid) == 0 && maybe_pid > 0) {
		target_pid = (pid_t)maybe_pid;
		spin_lock_irqsave(&stored_pid_lock, flags);
		stored_target_pid = target_pid;
		spin_unlock_irqrestore(&stored_pid_lock, flags);
	} else {
		spin_lock_irqsave(&stored_pid_lock, flags);
		target_pid = stored_target_pid;
		spin_unlock_irqrestore(&stored_pid_lock, flags);
	}

	if (!target_pid)
		return -EINVAL;

	rcu_read_lock();
	task = pid_task(find_pid_ns(target_pid, &init_pid_ns), PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (!task)
		return -ESRCH;

	set_cpus_allowed_ptr(task, cpu_possible_mask);
	put_task_struct(task);

	WRITE_ONCE(ax_total_affinity_resets,
		   READ_ONCE(ax_total_affinity_resets) + 1);

	return count;
}

/* -------------------------------------------------------------------------
 * Procfs Ops definition
 * ------------------------------------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops nta_pid_ops = {
	.proc_open = nta_pid_open,
	.proc_read = seq_read,
	.proc_write = nta_pid_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops nta_ops = {
	.proc_write = nta_write,
	.proc_lseek = noop_llseek,
};

static const struct proc_ops nta_reset_ops = {
	.proc_write = nta_reset_write,
	.proc_lseek = noop_llseek,
};
#else
static const struct file_operations nta_pid_ops = {
	.owner = THIS_MODULE,
	.open = nta_pid_open,
	.read = seq_read,
	.write = nta_pid_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations nta_ops = {
	.owner = THIS_MODULE,
	.write = nta_write,
	.llseek = noop_llseek,
};

static const struct file_operations nta_reset_ops = {
	.owner = THIS_MODULE,
	.write = nta_reset_write,
	.llseek = noop_llseek,
};
#endif

/* -------------------------------------------------------------------------
 * Init / Exit
 * ------------------------------------------------------------------------- */
int ax_named_thread_affinity_init(void)
{
	struct proc_dir_entry *entry;

	ax_named_affinity_dir = proc_mkdir("ax_named_thread_affinity", NULL);
	if (!ax_named_affinity_dir) {
		pr_err(AX_DRAGONITE_TAG "failed to create /proc/ax_named_thread_affinity\n");
		return -ENOMEM;
	}

	entry = proc_create("pid", 0666, ax_named_affinity_dir, &nta_pid_ops);
	if (!entry)
		goto err_pid;
	axd_proc_fixup_owner(entry);

	entry = proc_create("named_thread_affinity", 0222,
			    ax_named_affinity_dir, &nta_ops);
	if (!entry)
		goto err_nta;
	axd_proc_fixup_owner(entry);

	entry = proc_create("reset", 0222, ax_named_affinity_dir,
			    &nta_reset_ops);
	if (!entry)
		goto err_reset;
	axd_proc_fixup_owner(entry);

	return 0;

err_reset:
	remove_proc_entry("named_thread_affinity", ax_named_affinity_dir);
err_nta:
	remove_proc_entry("pid", ax_named_affinity_dir);
err_pid:
	remove_proc_entry("ax_named_thread_affinity", NULL);
	ax_named_affinity_dir = NULL;
	return -ENOMEM;
}

void ax_named_thread_affinity_exit(void)
{
	if (ax_named_affinity_dir) {
		remove_proc_entry("reset", ax_named_affinity_dir);
		remove_proc_entry("named_thread_affinity", ax_named_affinity_dir);
		remove_proc_entry("pid", ax_named_affinity_dir);
		remove_proc_entry("ax_named_thread_affinity", NULL);
	}
}
