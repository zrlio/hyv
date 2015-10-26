/*
 * Hybrid Virtualization (HyV) for Linux
 *
 * Author: Jonas Pfefferle <jpf@zurich.ibm.com>
 *
 * Copyright (C) 2015, IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *USA.
 */

#ifndef VHOST_HYV_EVENT_H_
#define VHOST_HYV_EVENT_H_

#include <hyv_event.h>

#include "vhost_hyv.h"

struct vhost_work;

void vhost_hyv_handle_evt(struct vhost_work *work);

void vhost_hyv_event_cleanup(struct vhost_hyv *vg);

static inline void vhost_hyv_signal_event(struct vhost_hyv *vg)
{
	eventfd_signal(vg->vq_evt.call_ctx, 1);
}

static inline int vhost_hyv_push_event(struct vhost_hyv *vg,
				       struct hyv_event event, bool signal)
{
	unsigned long flags;
	u32 retry = 0;

	if (!vg->evt_queue) {
		return -ENODEV;
	}

	/* llqueue is lock less but only single-consumer/producer
	 * we need private locks on both host/guest to ensure that */
	spin_lock_irqsave(&vg->evt_lock, flags);
	while (!LLQUEUE_PUSH(vg->evt_queue, vg->pfront, event)) {
		spin_unlock_irqrestore(&vg->evt_lock, flags);
		/* it is unlikely that we come in here
		 * kick the guest to empty the queue */
		if ((retry % (1 << 10)) == 0) {
			vhost_hyv_signal_event(vg);
		}
		if (retry++ == (1 << 20)) {
			return -ENOSPC;
		}
		spin_lock_irqsave(&vg->evt_lock, flags);
	}
	spin_unlock_irqrestore(&vg->evt_lock, flags);

	if (signal) {
		vhost_hyv_signal_event(vg);
	}

	return 0;
}

#endif /* VHOST_HYV_EVENT_H_ */
