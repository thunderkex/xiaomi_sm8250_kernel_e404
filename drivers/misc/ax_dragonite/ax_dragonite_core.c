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

#include "ax_dragonite.h"

struct proc_dir_entry *ax_dragonite_dir;
EXPORT_SYMBOL_GPL(ax_dragonite_dir);

static cpumask_t kswapd_pinned_mask;
static DEFINE_SPINLOCK(kswapd_pin_lock);

static struct ax_boost_entry boost_table[AX_MAX_BOOST_ENTRIES];
static unsigned long total_boost_count;
static DEFINE_MUTEX(boost_table_mutex);

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

	/* 2. Pin any kswapd and ksmd threads found in task list */
	rcu_read_lock();
	for_each_process_thread(g, t) {
		if ((t->flags & PF_KSWAPD) || strncmp(t->comm, "kswapd", 6) == 0 ||
		    strncmp(t->comm, "ksmd", 4) == 0) {
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
	char kbuf[48];
	char *ptr, *pid_str, *state_str, *level_str;
	int pid, boost_state = 1, boost_level = 2; /* default: acquire, heavy (nice -20) */
	struct task_struct *task;
	int i, target_slot = -1, orig_nice = 0;
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

	/* Accept "<pid> [state] [level]" (e.g. "1819", "1819 1", "1819 1 1", "1819 0") */
	pid_str = strsep(&ptr, " \t");
	if (!pid_str || kstrtoint(pid_str, 10, &pid) < 0 || pid <= 0) {
		pr_warn_ratelimited(AX_DRAGONITE_TAG "invalid boost pid: %s\n", kbuf);
		return -EINVAL;
	}

	if (ptr) {
		ptr = skip_spaces(ptr);
		state_str = strsep(&ptr, " \t");
		if (state_str && kstrtoint(state_str, 10, &boost_state) < 0)
			boost_state = 1;
	}

	if (ptr) {
		ptr = skip_spaces(ptr);
		level_str = strsep(&ptr, " \t");
		if (level_str && kstrtoint(level_str, 10, &boost_level) < 0)
			boost_level = 2;
	}

	if (boost_state > 0) {
		/* Boost Acquire: Level 1 = Light (-5), Level 2 = Heavy (-20) */
		int target_nice = (boost_level == 1) ? -5 : -20;
		int free_slot = -1;

		rcu_read_lock();
		task = find_task_by_vpid(pid);
		if (!task) {
			rcu_read_unlock();
			return -ESRCH;
		}
		get_task_struct(task);
		rcu_read_unlock();

		mutex_lock(&boost_table_mutex);
		for (i = 0; i < AX_MAX_BOOST_ENTRIES; i++) {
			if (boost_table[i].active && boost_table[i].pid == pid) {
				target_slot = i;
				break;
			}
			if (!boost_table[i].active && free_slot == -1)
				free_slot = i;
		}

		if (target_slot == -1) {
			if (free_slot == -1) {
				mutex_unlock(&boost_table_mutex);
				put_task_struct(task);
				pr_warn_ratelimited(AX_DRAGONITE_TAG "boost table full\n");
				return -ENOSPC;
			}
			target_slot = free_slot;
			boost_table[target_slot].pid = pid;
			boost_table[target_slot].saved_nice = task_nice(task);
			boost_table[target_slot].active = true;
		}
		boost_table[target_slot].level = boost_level;
		total_boost_count++;
		mutex_unlock(&boost_table_mutex);

		set_user_nice(task, target_nice);
		wake_up_process(task);
		put_task_struct(task);
	} else {
		/* Boost Release: restore saved prior nice value */
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

		orig_nice = boost_table[target_slot].saved_nice;
		boost_table[target_slot].active = false;
		boost_table[target_slot].pid = 0;
		mutex_unlock(&boost_table_mutex);

		rcu_read_lock();
		task = find_task_by_vpid(pid);
		if (task) {
			get_task_struct(task);
			rcu_read_unlock();
			set_user_nice(task, orig_nice);
			put_task_struct(task);
		} else {
			rcu_read_unlock();
		}
	}

	return count;
}

static int boost_show(struct seq_file *m, void *v)
{
	int i, active_count = 0;
	unsigned long total;

	mutex_lock(&boost_table_mutex);
	total = total_boost_count;
	seq_printf(m, "# pid saved_nice level\n");
	for (i = 0; i < AX_MAX_BOOST_ENTRIES; i++) {
		if (boost_table[i].active) {
			seq_printf(m, "%-8d %-10d %-5d\n",
				   boost_table[i].pid,
				   boost_table[i].saved_nice,
				   boost_table[i].level);
			active_count++;
		}
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
static int saved_vm_swappiness;
static unsigned int swappiness_lease_count;
static bool swappiness_override_active;
static DEFINE_SPINLOCK(swappiness_override_lock);

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

	spin_lock_irqsave(&swappiness_override_lock, flags);
	if (target_val < 0) {
		/* Release lease: decrement refcount; restore on final release */
		if (swappiness_lease_count > 0) {
			swappiness_lease_count--;
			if (swappiness_lease_count == 0 && swappiness_override_active) {
				vm_swappiness = saved_vm_swappiness;
				swappiness_override_active = false;
			}
		}
	} else if (target_val <= 200) {
		/* Acquire lease: save original value on initial acquisition */
		if (swappiness_lease_count == 0 && !swappiness_override_active) {
			saved_vm_swappiness = vm_swappiness;
			swappiness_override_active = true;
		}
		vm_swappiness = target_val;
		swappiness_lease_count++;
	} else {
		spin_unlock_irqrestore(&swappiness_override_lock, flags);
		pr_warn_ratelimited(AX_DRAGONITE_TAG "swappiness out of range (0-200): %d\n", target_val);
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
	seq_printf(m, "AxDragonite 4.19.404R-dragonite\n");
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
