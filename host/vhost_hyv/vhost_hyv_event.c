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

#include <linux/highmem.h>

#include <vhost.h>

#include <object_map.h>

#include "vhost_hyv_debug.h"

#include "vhost_hyv_event.h"

void vhost_hyv_handle_evt(struct vhost_work *work)
{
	struct vhost_virtqueue *vq =
	    container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_dev *dev = vq->dev;
	struct vhost_hyv *vg = container_of(vq, struct vhost_hyv, vq_evt);
	int head, out, in;
	unsigned long pages_pinned;
	struct page *page;
	void *data;

	dprint(DBG_EVT, "\n");

	if (vg->evt_queue) {
		/* this should not happen because we disabled notifications! */
		dprint(DBG_ON, "event queue is already set up!\n");
		return;
	}

	vhost_disable_notify(dev, vq);

	for (;;) {
		head = vhost_get_vq_desc(dev, vq, vq->iov, ARRAY_SIZE(vq->iov),
					 &out, &in, NULL, NULL);

		if (head < 0) {
			break;
		}

		if (vq->num == head) {
			if (vhost_enable_notify(dev, vq)) {
				vhost_disable_notify(dev, vq);
				continue;
			}
			break;
		}

		pages_pinned = get_user_pages_fast(
		    (unsigned long)vq->iov[0].iov_base, 1, 1, &page);
		if (pages_pinned < 0 || (unsigned long)pages_pinned != 1) {
			dprint(DBG_ON, "get_user_pages failed with %d",
			       (int)pages_pinned);
			return;
		}

		data = kmap(page);
		if (IS_ERR_OR_NULL(data)) {
			dprint(DBG_ON, "could not kmap page!\n");
			return;
		}
		vg->evt_queue = data;

		vhost_add_used(vq, head, 0);
	}
}

void vhost_hyv_event_cleanup(struct vhost_hyv *vg)
{
	dprint(DBG_EVT, "\n");

	if (vg->evt_queue) {
		struct page *page = kmap_to_page(vg->evt_queue);
		kunmap(page);
		put_page(page);
	}
	vg->evt_queue = NULL;
}
