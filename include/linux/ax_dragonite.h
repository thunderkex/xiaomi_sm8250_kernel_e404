/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AX_DRAGONITE_H
#define _LINUX_AX_DRAGONITE_H

struct task_struct;

#if IS_ENABLED(CONFIG_AX_DRAGONITE)
void ax_named_thread_affinity_apply(struct task_struct *p);
#else
static inline void ax_named_thread_affinity_apply(struct task_struct *p)
{
}
#endif

#endif /* _LINUX_AX_DRAGONITE_H */
