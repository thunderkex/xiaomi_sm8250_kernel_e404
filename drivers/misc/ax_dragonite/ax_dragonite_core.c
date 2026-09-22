// SPDX-License-Identifier: GPL-2.0
/*
 * AxDragonite Core Driver
 *
 * Exposes:
 *  - /proc/ax_dragonite/kswapd_pin: pins kswapd/ksmd kernel threads
 *  - /proc/ax_dragonite/boost: elevates priority of designated task (CFS/PELT)
 *  - /proc/ax_dragonite/swappiness_override: refcounted vm.swappiness lease
 *
 * All leases (boost, swappiness) auto-expire after AX_LEASE_TTL_MS.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/utsname.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/mmzone.h>
#include <linux/ratelimit.h>
#include <linux/swap.h>

#include "ax_dragonite.h"

struct proc_dir_entry *ax_dragonite_dir;
EXPORT_SYMBOL_GPL(ax_dragonite_dir);

static cpumask_t kswapd_pinned_mask;
static DEFINE_SPINLOCK(kswapd_pin_lock);

static struct ax_boost_entry boost_table[AX_MAX_BOOST_ENTRIES];
static unsigned long total_boost_count;
static DEFINE_MUTEX(boost_table_mutex);

/* swappiness lease state (declared early: shared with the lease reaper) */
static int saved_vm_swappiness;
static unsigned int swappiness_lease_count;
static bool swappiness_override_active;
static unsigned long swappiness_expires;
static DEFINE_SPINLOCK(swappiness_override_lock);

static void ax_lease_reap_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ax_lease_work, ax_lease_reap_fn);

static inline void ax_lease_kick(void)
{
	/* no-op if already pending */
	schedule_delayed_work(&ax_lease_work, msecs_to_jiffies(AX_LEASE_REAP_MS));
}

/* CPUMask parser supporting hex ("0f", "0x0f") and cpulist ("0-3", "0,1,2") */
int ax_parse_cpumask(const char *buf, cpumask_t *mask)
{
	unsigned long raw_mask = 0;
	int ret;

	if (!buf || !mask)
		return -EINVAL;

	cpumask_clear(mask);

	/* cpulist format containing '-' or ',' */
	if (strchr(buf, '-') || strchr(buf, ',')) {
		ret = cpulist_parse(buf, mask);
		if (ret)
			return ret;
		goto clamp;
	}

	/* hex first ("ff", "0x0f"), then base-0 fallback */
	ret = kstrtoul(buf, 16, &raw_mask);
	if (ret < 0)
		ret = kstrtoul(buf, 0, &raw_mask);
	if (ret < 0)
		return ret;

#if BITS_PER_LONG == 64
	mask->bits[0] = raw_mask;
#else
	mask->bits[0] = raw_mask & 0xFFFFFFFF;
#endif
clamp:
	/* never hand set_cpus_allowed_ptr() bits for CPUs that cannot exist */
	cpumask_and(mask, mask, cpu_possible_mask);
	return 0;
}
EXPORT_SYMBOL_GPL(ax_parse_cpumask);

/* -------------------------------------------------------------------------
 * /proc/ax_dragonite/kswapd_pin
 * ------------------------------------------------------------------------- */
#define AX_PIN_MAX_TASKS 16

static ssize_t kswapd_pin_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char kbuf[64];
	cpumask_t new_mask;
	struct task_struct *g, *found[AX_PIN_MAX_TASKS];
	unsigned long flags;
	size_t len = min(count, sizeof(kbuf) - 1);
	int ret, i, n = 0;

	if (!ax_dragonite_is_authorized()) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG
				    "unauthorized kswapd_pin write from uid %u\n",
				    from_kuid(&init_user_ns, current_euid()));
		return -EPERM;
	}

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	ret = ax_parse_cpumask(strim(kbuf), &new_mask);
	if (ret < 0 || cpumask_empty(&new_mask)) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "invalid cpumask format: %s\n", kbuf);
		return -EINVAL;
	}

	spin_lock_irqsave(&kswapd_pin_lock, flags);
	cpumask_copy(&kswapd_pinned_mask, &new_mask);
	spin_unlock_irqrestore(&kswapd_pin_lock, flags);

	/*
	 * kswapd and ksmd are single-threaded kernel processes, so walking
	 * process leaders is enough (much cheaper than every thread) and the
	 * PF_KTHREAD test stops an app thread that merely *names* itself
	 * "kswapd"/"ksmd" from being re-pinned.
	 *
	 * Tasks are collected (with a reference) under RCU and acted on after
	 * rcu_read_unlock(): set_cpus_allowed_ptr() may sleep, and dropping RCU
	 * in the middle of the list walk would leave the iterator pointing at a
	 * task that could already have been freed.
	 */
	rcu_read_lock();
	for_each_process(g) {
		if (!(g->flags & PF_KTHREAD))
			continue;
		if (!(g->flags & PF_KSWAPD) &&
		    strncmp(g->comm, "kswapd", 6) != 0 &&
		    strncmp(g->comm, "ksmd", 4) != 0)
			continue;
		if (n == AX_PIN_MAX_TASKS)
			break;
		get_task_struct(g);
		found[n++] = g;
	}
	rcu_read_unlock();

	for (i = 0; i < n; i++) {
		set_cpus_allowed_ptr(found[i], &new_mask);
		put_task_struct(found[i]);
	}

	return count;
}

static int kswapd_pin_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	char mask_str[64];

	spin_lock_irqsave(&kswapd_pin_lock, flags);
	cpumap_print_to_pagebuf(false, mask_str, &kswapd_pinned_mask);
	spin_unlock_irqrestore(&kswapd_pin_lock, flags);

	seq_printf(m, "%s\n", strim(mask_str));
	return 0;
}

static int kswapd_pin_open(struct inode *inode, struct file *file)
{
	return single_open(file, kswapd_pin_show, NULL);
}

/* -------------------------------------------------------------------------
 * /proc/ax_dragonite/boost
 *
 * Format: "<pid> [state] [level]"   state: 1=acquire (default) 0=release
 *                                    level: 1=Light(-5) 2=Heavy(-20, default)
 * ------------------------------------------------------------------------- */
static bool ax_boost_task_alive(struct ax_boost_entry *e)
{
	bool alive;

	rcu_read_lock();
	alive = pid_task(e->spid, PIDTYPE_PID) != NULL;
	rcu_read_unlock();
	return alive;
}

/* Caller holds boost_table_mutex and e->active is true. */
static void ax_boost_release_locked(struct ax_boost_entry *e)
{
	struct task_struct *task;

	rcu_read_lock();
	task = pid_task(e->spid, PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (task) {
		/*
		 * Only undo our own change. If the framework re-niced the task
		 * during the lease (e.g. moved it to background), that newer
		 * decision wins and must not be overwritten.
		 */
		if (task_nice(task) == e->applied_nice)
			set_user_nice(task, e->saved_nice);
		put_task_struct(task);
	}

	put_pid(e->spid);
	e->spid = NULL;
	e->pid = 0;
	e->active = false;
}

static ssize_t boost_write(struct file *file, const char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	char kbuf[48];
	char *ptr, *tok;
	int pid, boost_state = 1, boost_level = 2;
	struct pid *spid;
	struct task_struct *task;
	size_t len = min(count, sizeof(kbuf) - 1);
	int i, target_slot = -1, free_slot = -1, target_nice;

	if (!ax_dragonite_is_authorized()) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG
				    "unauthorized boost write from uid %u\n",
				    from_kuid(&init_user_ns, current_euid()));
		return -EPERM;
	}

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	ptr = strim(kbuf);

	tok = strsep(&ptr, " \t");
	if (!tok || kstrtoint(tok, 10, &pid) < 0 || pid <= 0) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "invalid boost pid: %s\n", kbuf);
		return -EINVAL;
	}

	/*
	 * Malformed state/level must be rejected, never defaulted: a garbled
	 * *release* silently turning into an *acquire* would leave a task at
	 * nice -20.
	 */
	if (ptr) {
		ptr = skip_spaces(ptr);
		tok = strsep(&ptr, " \t");
		if (tok && *tok && kstrtoint(tok, 10, &boost_state) < 0)
			return -EINVAL;
	}
	if (ptr) {
		ptr = skip_spaces(ptr);
		tok = strsep(&ptr, " \t");
		if (tok && *tok && kstrtoint(tok, 10, &boost_level) < 0)
			return -EINVAL;
	}
	if (boost_level != 1 && boost_level != 2)
		return -EINVAL;

	if (boost_state <= 0) {
		/* ---- release ---- */
		mutex_lock(&boost_table_mutex);
		for (i = 0; i < AX_MAX_BOOST_ENTRIES; i++) {
			if (boost_table[i].active && boost_table[i].pid == pid) {
				target_slot = i;
				break;
			}
		}
		if (target_slot == -1) {
			mutex_unlock(&boost_table_mutex);
			return -ENOENT;
		}
		ax_boost_release_locked(&boost_table[target_slot]);
		mutex_unlock(&boost_table_mutex);
		return count;
	}

	/* ---- acquire ---- */
	target_nice = (boost_level == 1) ? -5 : -20;

	spid = find_get_pid(pid);
	if (!spid)
		return -ESRCH;

	rcu_read_lock();
	task = pid_task(spid, PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	if (!task) {
		put_pid(spid);
		return -ESRCH;
	}
	if (task->flags & PF_KTHREAD) {
		put_task_struct(task);
		put_pid(spid);
		return -EPERM;
	}

	mutex_lock(&boost_table_mutex);
	for (i = 0; i < AX_MAX_BOOST_ENTRIES; i++) {
		struct ax_boost_entry *e = &boost_table[i];

		/* reclaim slots whose task exited or lease expired */
		if (e->active && (time_after(jiffies, e->expires) || !ax_boost_task_alive(e)))
			ax_boost_release_locked(e);

		if (e->active && e->spid == spid) {
			target_slot = i;
			break;
		}
		if (!e->active && free_slot == -1)
			free_slot = i;
	}

	if (target_slot == -1) {
		if (free_slot == -1) {
			mutex_unlock(&boost_table_mutex);
			put_task_struct(task);
			put_pid(spid);
			pr_warn_ratelimited(AX_DRAGONITE_TAG "boost table full\n");
			return -ENOSPC;
		}
		target_slot = free_slot;
		boost_table[target_slot].spid = spid;	/* table now owns this ref */
		boost_table[target_slot].pid = pid;
		boost_table[target_slot].saved_nice = task_nice(task);
		boost_table[target_slot].active = true;
	} else {
		put_pid(spid);	/* entry already holds its own ref */
	}
	boost_table[target_slot].level = boost_level;
	boost_table[target_slot].applied_nice = target_nice;
	boost_table[target_slot].expires = jiffies + msecs_to_jiffies(AX_LEASE_TTL_MS);
	total_boost_count++;

	/*
	 * set_user_nice() stays inside the mutex: dropping it first lets a
	 * concurrent release run *before* our nice change and then leaves the
	 * task at -20 with no table entry to ever undo it. It also re-queues
	 * the task itself, so no wake_up_process() (which would only inject a
	 * spurious wakeup into interruptible sleepers).
	 */
	set_user_nice(task, target_nice);
	mutex_unlock(&boost_table_mutex);

	put_task_struct(task);
	ax_lease_kick();
	return count;
}

static int boost_show(struct seq_file *m, void *v)
{
	int i, active_count = 0;
	unsigned long total, now = jiffies;

	mutex_lock(&boost_table_mutex);
	total = total_boost_count;
	seq_printf(m, "# pid saved_nice level ttl_ms\n");
	for (i = 0; i < AX_MAX_BOOST_ENTRIES; i++) {
		struct ax_boost_entry *e = &boost_table[i];

		if (!e->active)
			continue;
		seq_printf(m, "%-8d %-10d %-5d %u\n", e->pid, e->saved_nice, e->level,
			   time_after(e->expires, now) ?
			   jiffies_to_msecs(e->expires - now) : 0);
		active_count++;
	}
	mutex_unlock(&boost_table_mutex);

	seq_printf(m, "active_boosts: %d\ntotal_boosts: %lu\n", active_count, total);
	return 0;
}

static int boost_open(struct inode *inode, struct file *file)
{
	return single_open(file, boost_show, NULL);
}

/* -------------------------------------------------------------------------
 * /proc/ax_dragonite/swappiness_override
 * ------------------------------------------------------------------------- */
static ssize_t swappiness_override_write(struct file *file, const char __user *ubuf,
					 size_t count, loff_t *ppos)
{
	char kbuf[32];
	int target_val;
	unsigned long flags;
	size_t len = min(count, sizeof(kbuf) - 1);

	if (!ax_dragonite_is_authorized()) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG
				    "unauthorized swappiness_override write from uid %u\n",
				    from_kuid(&init_user_ns, current_euid()));
		return -EPERM;
	}

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	if (kstrtoint(strim(kbuf), 10, &target_val) < 0) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "invalid swappiness value: %s\n", kbuf);
		return -EINVAL;
	}
	if (target_val > 200) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "swappiness out of range (0-200): %d\n",
				    target_val);
		return -EINVAL;
	}

	spin_lock_irqsave(&swappiness_override_lock, flags);
	if (target_val < 0) {
		/* release: drop one reference, restore on the last one */
		if (swappiness_lease_count > 0 && --swappiness_lease_count == 0 &&
		    swappiness_override_active) {
			vm_swappiness = saved_vm_swappiness;
			swappiness_override_active = false;
		}
	} else {
		/* acquire: remember the pre-boost value only on the first lease */
		if (!swappiness_override_active) {
			saved_vm_swappiness = vm_swappiness;
			swappiness_override_active = true;
			swappiness_lease_count = 0;
		}
		vm_swappiness = target_val;
		swappiness_lease_count++;
		swappiness_expires = jiffies + msecs_to_jiffies(AX_LEASE_TTL_MS);
	}
	spin_unlock_irqrestore(&swappiness_override_lock, flags);

	if (target_val >= 0)
		ax_lease_kick();
	return count;
}

static int swappiness_override_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	bool active;
	int cur_swappiness, orig_swappiness;
	unsigned int lease_cnt;

	spin_lock_irqsave(&swappiness_override_lock, flags);
	active = swappiness_override_active;
	cur_swappiness = vm_swappiness;
	orig_swappiness = saved_vm_swappiness;
	lease_cnt = swappiness_lease_count;
	spin_unlock_irqrestore(&swappiness_override_lock, flags);

	seq_printf(m, "active: %d\ncurrent_swappiness: %d\nsaved_original: %d\nlease_count: %u\n",
		   active ? 1 : 0, cur_swappiness, orig_swappiness, lease_cnt);
	return 0;
}

static int swappiness_override_open(struct inode *inode, struct file *file)
{
	return single_open(file, swappiness_override_show, NULL);
}

/* -------------------------------------------------------------------------
 * Lease reaper: enforces AX_LEASE_TTL_MS for boosts and the swappiness lease
 * and drops boost entries whose task died without a release.
 * ------------------------------------------------------------------------- */
static void ax_lease_reap_fn(struct work_struct *work)
{
	unsigned long now = jiffies, flags;
	bool more = false;
	int i;

	mutex_lock(&boost_table_mutex);
	for (i = 0; i < AX_MAX_BOOST_ENTRIES; i++) {
		struct ax_boost_entry *e = &boost_table[i];

		if (!e->active)
			continue;
		if (time_after(now, e->expires) || !ax_boost_task_alive(e))
			ax_boost_release_locked(e);
		else
			more = true;
	}
	mutex_unlock(&boost_table_mutex);

	spin_lock_irqsave(&swappiness_override_lock, flags);
	if (swappiness_override_active) {
		if (time_after(now, swappiness_expires)) {
			vm_swappiness = saved_vm_swappiness;
			swappiness_override_active = false;
			swappiness_lease_count = 0;
		} else {
			more = true;
		}
	}
	spin_unlock_irqrestore(&swappiness_override_lock, flags);

	if (more)
		ax_lease_kick();
}

/* -------------------------------------------------------------------------
 * /proc/ax_dragonite/version
 * ------------------------------------------------------------------------- */
static int version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "AxDragonite %s\n", init_utsname()->release);
	return 0;
}

static int version_open(struct inode *inode, struct file *file)
{
	return single_open(file, version_show, NULL);
}

/* -------------------------------------------------------------------------
 * Procfs Ops definition (Linux 4.19 and 5.6+ compatible)
 * ------------------------------------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops kswapd_pin_ops = {
	.proc_open = kswapd_pin_open,
	.proc_read = seq_read,
	.proc_write = kswapd_pin_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops boost_ops = {
	.proc_open = boost_open,
	.proc_read = seq_read,
	.proc_write = boost_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops swappiness_override_ops = {
	.proc_open = swappiness_override_open,
	.proc_read = seq_read,
	.proc_write = swappiness_override_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops version_ops = {
	.proc_open = version_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#else
static const struct file_operations kswapd_pin_ops = {
	.owner = THIS_MODULE,
	.open = kswapd_pin_open,
	.read = seq_read,
	.write = kswapd_pin_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations boost_ops = {
	.owner = THIS_MODULE,
	.open = boost_open,
	.read = seq_read,
	.write = boost_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations swappiness_override_ops = {
	.owner = THIS_MODULE,
	.open = swappiness_override_open,
	.read = seq_read,
	.write = swappiness_override_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations version_ops = {
	.owner = THIS_MODULE,
	.open = version_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

/* -------------------------------------------------------------------------
 * Module Init / Exit
 * ------------------------------------------------------------------------- */
static int __init ax_dragonite_core_init(void)
{
	cpumask_clear(&kswapd_pinned_mask);

	ax_dragonite_dir = proc_mkdir("ax_dragonite", NULL);
	if (!ax_dragonite_dir) {
		pr_err(AX_DRAGONITE_TAG "failed to create /proc/ax_dragonite\n");
		return -ENOMEM;
	}

	proc_create("kswapd_pin", 0640, ax_dragonite_dir, &kswapd_pin_ops);
	proc_create("boost", 0640, ax_dragonite_dir, &boost_ops);
	proc_create("swappiness_override", 0640, ax_dragonite_dir, &swappiness_override_ops);
	proc_create("version", 0444, ax_dragonite_dir, &version_ops);

	ax_named_thread_affinity_init();

	pr_info(AX_DRAGONITE_TAG "driver initialized successfully\n");
	return 0;
}

static void __exit ax_dragonite_core_exit(void)
{
	cancel_delayed_work_sync(&ax_lease_work);
	ax_named_thread_affinity_exit();

	if (ax_dragonite_dir) {
		remove_proc_entry("version", ax_dragonite_dir);
		remove_proc_entry("swappiness_override", ax_dragonite_dir);
		remove_proc_entry("boost", ax_dragonite_dir);
		remove_proc_entry("kswapd_pin", ax_dragonite_dir);
		remove_proc_entry("ax_dragonite", NULL);
	}

	pr_info(AX_DRAGONITE_TAG "driver exited\n");
}

module_init(ax_dragonite_core_init);
module_exit(ax_dragonite_core_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("thunderkex <thunderkex@gmail.com>");
MODULE_DESCRIPTION("AxDragonite Kernel Performance Interface");
