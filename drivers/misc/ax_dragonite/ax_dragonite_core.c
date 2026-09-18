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

#include "ax_dragonite.h"

struct proc_dir_entry *ax_dragonite_dir;
EXPORT_SYMBOL_GPL(ax_dragonite_dir);

static cpumask_t kswapd_pinned_mask;
static DEFINE_SPINLOCK(kswapd_pin_lock);

static int last_boosted_pid;
static unsigned long boost_count;
static DEFINE_SPINLOCK(boost_lock);

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

		if (pgdat && pgdat->kswapd) {
			get_task_struct(pgdat->kswapd);
			set_cpus_allowed_ptr(pgdat->kswapd, &new_mask);
			put_task_struct(pgdat->kswapd);
		}
	}

	/* 2. Pin any kswapd threads found in task list */
	rcu_read_lock();
	for_each_process_thread(g, t) {
		if ((t->flags & PF_KSWAPD) || strncmp(t->comm, "kswapd", 6) == 0) {
			get_task_struct(t);
			rcu_read_unlock();
			set_cpus_allowed_ptr(t, &new_mask);
			put_task_struct(t);
			rcu_read_lock();
		}
	}
	rcu_read_unlock();

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
	char kbuf[32];
	char *ptr, *pid_str;
	int pid, boost_val = 1, ret;
	struct task_struct *task;
	unsigned long flags;
	size_t len = min(count, sizeof(kbuf) - 1);

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

	/* Accept "<pid>" or "<pid> <state>" (e.g. "1819 1" boost start, "1819 0" boost release) */
	pid_str = strsep(&ptr, " \t");
	if (!pid_str || kstrtoint(pid_str, 10, &pid) < 0 || pid <= 0) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "invalid boost pid: %s\n", kbuf);
		return -EINVAL;
	}

	if (ptr) {
		char *val_str = strim(ptr);
		if (kstrtoint(val_str, 10, &boost_val) < 0)
			boost_val = 1;
	}

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(task);
	rcu_read_unlock();

	spin_lock_irqsave(&boost_lock, flags);
	last_boosted_pid = pid;
	boost_count++;
	spin_unlock_irqrestore(&boost_lock, flags);

	/*
	 * Fallback path for CFS / PELT kernel (WALT absent):
	 * When boost_val > 0: raise task nice to -20 and wake up.
	 * When boost_val == 0: restore nice to 0 (normal priority).
	 */
	if (boost_val > 0) {
		set_user_nice(task, -20);
		wake_up_process(task);
	} else {
		set_user_nice(task, 0);
	}
	put_task_struct(task);

	return count;
}

static int boost_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	int last_pid;
	unsigned long total;

	spin_lock_irqsave(&boost_lock, flags);
	last_pid = last_boosted_pid;
	total = boost_count;
	spin_unlock_irqrestore(&boost_lock, flags);

	seq_printf(m, "last_boosted_pid: %d\ntotal_boosts: %lu\n", last_pid, total);
	return 0;
}

static int boost_open(struct inode *inode, struct file *file)
{
	return single_open(file, boost_show, NULL);
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

	proc_create("kswapd_pin", 0664, ax_dragonite_dir, &kswapd_pin_ops);
	proc_create("boost", 0664, ax_dragonite_dir, &boost_ops);

	ax_named_thread_affinity_init(ax_dragonite_dir);

	pr_info(AX_DRAGONITE_TAG "driver initialized successfully\n");
	return 0;
}

static void __exit ax_dragonite_core_exit(void)
{
	ax_named_thread_affinity_exit();

	if (ax_dragonite_dir) {
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
