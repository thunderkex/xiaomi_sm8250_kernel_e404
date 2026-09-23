// SPDX-License-Identifier: GPL-2.0
/*
 * AxDragonite Core Driver
 *
 * Exposes:
 *  - /proc/ax_dragonite/kswapd_pin: pins kswapd threads across NUMA nodes
 *  - /proc/ax_dragonite/boost: elevates priority of designated task (CFS/PELT)
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/nodemask.h>
#include <linux/mmzone.h>
#include <linux/ratelimit.h>
#include <linux/swap.h>
#include <linux/cpuhotplug.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/utsname.h>

#include "ax_dragonite.h"

struct proc_dir_entry *ax_dragonite_dir;
EXPORT_SYMBOL_GPL(ax_dragonite_dir);

static cpumask_t kswapd_pinned_mask;
static DEFINE_SPINLOCK(kswapd_pin_lock);
static enum cpuhp_state ax_kswapd_hp_state;

static int ax_kswapd_cpu_online(unsigned int cpu)
{
	unsigned long flags;
	cpumask_t mask;
	int nid;

	spin_lock_irqsave(&kswapd_pin_lock, flags);
	cpumask_copy(&mask, &kswapd_pinned_mask);
	spin_unlock_irqrestore(&kswapd_pin_lock, flags);

	if (cpumask_empty(&mask))
		return 0;

	/*
	 * pgdat->kswapd is a plain (non-__rcu) pointer, but every task_struct
	 * is itself freed via call_rcu() at the end of its life regardless of
	 * how a pointer to it is stored; taking a reference to the task while
	 * still inside rcu_read_lock() is what keeps get_task_struct() from
	 * touching already-freed memory if kswapd_stop() races with us here
	 * (this mirrors how pid_task()/for_each_process() readers work).
	 */
	for_each_online_node(nid) {
		struct pglist_data *pgdat = NODE_DATA(nid);
		struct task_struct *k;

		rcu_read_lock();
		k = pgdat ? READ_ONCE(pgdat->kswapd) : NULL;
		if (k)
			get_task_struct(k);
		rcu_read_unlock();

		if (k) {
			set_cpus_allowed_ptr(k, &mask);
			put_task_struct(k);
		}
	}

	return 0;
}

static struct ax_boost_entry boost_table[AX_MAX_BOOST_ENTRIES];
static unsigned long total_boost_count;
static DEFINE_MUTEX(boost_table_mutex);

static void ax_boost_reap_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ax_boost_work, ax_boost_reap_fn);

static inline void ax_boost_lease_kick(void)
{
	schedule_delayed_work(&ax_boost_work, msecs_to_jiffies(1000));
}

/* Caller holds boost_table_mutex. Restores nice only if still ours to undo. */
static void ax_boost_release_locked(struct ax_boost_entry *e)
{
	struct task_struct *task;

	rcu_read_lock();
	task = pid_task(e->spid, PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (task) {
		if (task_nice(task) == e->applied_nice)
			set_user_nice(task, e->saved_nice);
		put_task_struct(task);
	}

	put_pid(e->spid);
	e->spid = NULL;
	e->pid = 0;
	e->active = false;
}

static void ax_boost_reap_fn(struct work_struct *work)
{
	unsigned long now = jiffies;
	bool more = false;
	int i;

	mutex_lock(&boost_table_mutex);
	for (i = 0; i < AX_MAX_BOOST_ENTRIES; i++) {
		struct ax_boost_entry *e = &boost_table[i];
		bool alive;

		if (!e->active)
			continue;

		rcu_read_lock();
		alive = pid_task(e->spid, PIDTYPE_PID) != NULL;
		rcu_read_unlock();

		if (!alive || time_after_eq(now, e->expires))
			ax_boost_release_locked(e);
		else
			more = true;
	}
	mutex_unlock(&boost_table_mutex);

	if (more)
		ax_boost_lease_kick();
}

/* CPUMask parser supporting hex ("0f", "0x0f") and cpulist ("0-3", "0,1,2") */
int ax_parse_cpumask(const char *buf, cpumask_t *mask)
{
	unsigned long raw_mask = 0;
	int ret;

	if (!buf || !mask)
		return -EINVAL;

	cpumask_clear(mask);

	/* Check if it's cpulist format containing '-' or ',' */
	if (strchr(buf, '-') || strchr(buf, ',')) {
		ret = cpulist_parse(buf, mask);
		if (!ret)
			return 0;
	}

	/* Try hex parse first (supports "ff", "f", "0x0f", "0f"), fallback to base 0 */
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
	return 0;
}
EXPORT_SYMBOL_GPL(ax_parse_cpumask);

/* -------------------------------------------------------------------------
 * /proc/ax_dragonite/kswapd_pin
 * ------------------------------------------------------------------------- */
static ssize_t kswapd_pin_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char kbuf[64];
	cpumask_t new_mask;
	struct task_struct *g, *t;
	unsigned long flags;
	size_t len = min(count, sizeof(kbuf) - 1);
	int ret, nid;

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

	/* 1. Pin NUMA node kswapd tasks directly via pgdat */
	for_each_online_node(nid) {
		struct pglist_data *pgdat = NODE_DATA(nid);
		struct task_struct *k;

		rcu_read_lock();
		k = pgdat ? READ_ONCE(pgdat->kswapd) : NULL;
		if (k)
			get_task_struct(k);
		rcu_read_unlock();

		if (k) {
			set_cpus_allowed_ptr(k, &new_mask);
			put_task_struct(k);
		}
	}

#define AX_PIN_MAX_TASKS 16

	/* 2. Pin any kswapd and ksmd threads found in task list */
	{
		struct task_struct *found[AX_PIN_MAX_TASKS];
		int i, n = 0;

		rcu_read_lock();
		for_each_process_thread(g, t) {
			if ((t->flags & PF_KSWAPD) ||
			    strncmp(t->comm, "kswapd", 6) == 0 ||
			    strncmp(t->comm, "ksmd", 4) == 0) {
				if (n < AX_PIN_MAX_TASKS) {
					get_task_struct(t);
					found[n++] = t;
				}
			}
		}
		rcu_read_unlock();

		for (i = 0; i < n; i++) {
			set_cpus_allowed_ptr(found[i], &new_mask);
			put_task_struct(found[i]);
		}
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
 * ------------------------------------------------------------------------- */
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

	if (boost_level != 1 && boost_level != 2) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "invalid boost level: %d\n",
				    boost_level);
		return -EINVAL;
	}

	if (boost_state <= 0) {
		/* Boost Release: restore saved prior nice value */
		mutex_lock(&boost_table_mutex);
		for (i = 0; i < AX_MAX_BOOST_ENTRIES; i++) {
			struct ax_boost_entry *e = &boost_table[i];

			if (e->active && e->pid == pid) {
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

	/* Boost Acquire: Level 1 = Light (-5), Level 2 = Heavy (-20) */
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
		bool alive;

		/* Garbage collect slots whose task exited without release */
		if (e->active) {
			rcu_read_lock();
			alive = pid_task(e->spid, PIDTYPE_PID) != NULL;
			rcu_read_unlock();
			if (!alive) {
				put_pid(e->spid);
				e->spid = NULL;
				e->pid = 0;
				e->active = false;
			}
		}

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
		boost_table[target_slot].spid = spid;
		boost_table[target_slot].pid = pid;
		boost_table[target_slot].saved_nice = task_nice(task);
		boost_table[target_slot].active = true;
	} else {
		put_pid(spid);
	}

	boost_table[target_slot].applied_nice = target_nice;
	boost_table[target_slot].level = boost_level;
	boost_table[target_slot].expires = jiffies +
					    msecs_to_jiffies(AX_BOOST_LEASE_TTL_MS);
	total_boost_count++;

	/*
	 * set_user_nice() stays inside the mutex: dropping it first lets a
	 * concurrent release() for this same pid run first, see the old
	 * (pre-boost) nice value, and clear this entry — after which
	 * set_user_nice() below would still apply -20/-5 with no entry left
	 * to ever undo it. set_user_nice() already requeues the task, so no
	 * wake_up_process() is needed (it only risks a spurious wakeup for a
	 * task currently in interruptible sleep).
	 */
	set_user_nice(task, target_nice);
	mutex_unlock(&boost_table_mutex);

	put_task_struct(task);
	ax_boost_lease_kick();

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
		bool alive;

		if (!e->active)
			continue;

		rcu_read_lock();
		alive = pid_task(e->spid, PIDTYPE_PID) != NULL;
		rcu_read_unlock();

		if (!alive) {
			put_pid(e->spid);
			e->spid = NULL;
			e->pid = 0;
			e->active = false;
			continue;
		}
		seq_printf(m, "%-8d %-10d %-5d %u\n",
			   e->pid, e->saved_nice, e->level,
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
#define AX_SWAPPINESS_LEASE_TTL_MS 15000

static int saved_vm_swappiness;
static int applied_vm_swappiness;
static unsigned int swappiness_lease_count;
static bool swappiness_override_active;
static unsigned long swappiness_expires;
static DEFINE_SPINLOCK(swappiness_override_lock);

static void ax_swappiness_reap_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ax_swappiness_work, ax_swappiness_reap_fn);

static void ax_swappiness_reap_fn(struct work_struct *work)
{
	unsigned long flags;

	spin_lock_irqsave(&swappiness_override_lock, flags);
	if (swappiness_override_active &&
	    time_after_eq(jiffies, swappiness_expires)) {
		/* Only restore if userspace sysctl has not overwritten it */
		if (vm_swappiness == applied_vm_swappiness)
			vm_swappiness = saved_vm_swappiness;
		swappiness_override_active = false;
		swappiness_lease_count = 0;
	}
	spin_unlock_irqrestore(&swappiness_override_lock, flags);
}

static ssize_t swappiness_override_write(struct file *file, const char __user *ubuf,
					 size_t count, loff_t *ppos)
{
	char kbuf[32];
	int target_val;
	unsigned long flags, ttl;
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

	spin_lock_irqsave(&swappiness_override_lock, flags);
	if (target_val < 0) {
		/* Release lease: decrement refcount; restore on final release */
		if (swappiness_lease_count > 0) {
			swappiness_lease_count--;
			if (swappiness_lease_count == 0 && swappiness_override_active) {
				if (vm_swappiness == applied_vm_swappiness)
					vm_swappiness = saved_vm_swappiness;
				swappiness_override_active = false;
				cancel_delayed_work(&ax_swappiness_work);
			}
		}
	} else if (target_val <= 200) {
		/* Acquire lease: save original value on initial acquisition */
		if (swappiness_lease_count == 0 && !swappiness_override_active) {
			saved_vm_swappiness = vm_swappiness;
			swappiness_override_active = true;
		}
		applied_vm_swappiness = target_val;
		vm_swappiness = target_val;
		swappiness_lease_count++;
		ttl = msecs_to_jiffies(AX_SWAPPINESS_LEASE_TTL_MS);
		swappiness_expires = jiffies + ttl;
		mod_delayed_work(system_wq, &ax_swappiness_work, ttl);
	} else {
		spin_unlock_irqrestore(&swappiness_override_lock, flags);
		pr_warn_ratelimited(AX_DRAGONITE_TAG "swappiness out of range (0-200): %d\n",
				    target_val);
		return -EINVAL;
	}
	spin_unlock_irqrestore(&swappiness_override_lock, flags);

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
	struct proc_dir_entry *entry;
	int ret;

	cpumask_clear(&kswapd_pinned_mask);

	ax_dragonite_dir = proc_mkdir("ax_dragonite", NULL);
	if (!ax_dragonite_dir) {
		pr_err(AX_DRAGONITE_TAG "failed to create /proc/ax_dragonite\n");
		return -ENOMEM;
	}

	entry = proc_create("kswapd_pin", 0640, ax_dragonite_dir,
			    &kswapd_pin_ops);
	if (!entry)
		goto err_kswapd_pin;

	entry = proc_create("boost", 0640, ax_dragonite_dir, &boost_ops);
	if (!entry)
		goto err_boost;

	entry = proc_create("swappiness_override", 0640, ax_dragonite_dir,
			    &swappiness_override_ops);
	if (!entry)
		goto err_swappiness;

	entry = proc_create("version", 0444, ax_dragonite_dir, &version_ops);
	if (!entry)
		goto err_version;

	ret = ax_named_thread_affinity_init();
	if (ret)
		goto err_affinity;

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					"ax_dragonite/kswapd:online",
					ax_kswapd_cpu_online, NULL);
	if (ret > 0)
		ax_kswapd_hp_state = ret;

	pr_info(AX_DRAGONITE_TAG "driver initialized successfully\n");
	return 0;

err_affinity:
	remove_proc_entry("version", ax_dragonite_dir);
err_version:
	remove_proc_entry("swappiness_override", ax_dragonite_dir);
err_swappiness:
	remove_proc_entry("boost", ax_dragonite_dir);
err_boost:
	remove_proc_entry("kswapd_pin", ax_dragonite_dir);
err_kswapd_pin:
	remove_proc_entry("ax_dragonite", NULL);
	ax_dragonite_dir = NULL;
	return -ENOMEM;
}

static void __exit ax_dragonite_core_exit(void)
{
	int i;

	if (ax_kswapd_hp_state)
		cpuhp_remove_state_nocalls(ax_kswapd_hp_state);

	ax_named_thread_affinity_exit();

	mutex_lock(&boost_table_mutex);
	for (i = 0; i < AX_MAX_BOOST_ENTRIES; i++) {
		if (boost_table[i].active && boost_table[i].spid) {
			put_pid(boost_table[i].spid);
			boost_table[i].spid = NULL;
			boost_table[i].active = false;
		}
	}
	mutex_unlock(&boost_table_mutex);

	cancel_delayed_work_sync(&ax_swappiness_work);
	cancel_delayed_work_sync(&ax_boost_work);

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
