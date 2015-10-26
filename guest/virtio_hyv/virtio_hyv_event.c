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

#include <linux/virtio.h>

#include <rdma/ib_verbs.h>

#include <hyv_event.h>

#include "hyv.h"
#include "virtio_hyv.h"
#include "virtio_hyv_debug.h"

#include "virtio_hyv_event.h"

int virtio_hyv_create_event_queue(struct virtio_hyv *vg)
{
	struct scatterlist sg;
	struct virtio_hyv_vq *vq = &vg->vq_evt;
	unsigned long flags;
	int ret;

	dprint(DBG_EVT, "\n");

	spin_lock_init(&vg->evt_lock);

	vg->evt_queue = (struct hyv_event_queue *)__get_free_page(GFP_USER);
	if (!vg->evt_queue) {
		dprint(DBG_ON, "could not allocate page\n");
		return -ENOMEM;
	}
	LLQUEUE_INIT(vg->evt_queue);

	sg_init_one(&sg, vg->evt_queue, PAGE_SIZE);

	spin_lock_irqsave(&vq->lock, flags);
	ret = virtqueue_add_inbuf(vq->vq, &sg, 1, vg->evt_queue, GFP_ATOMIC);
	if (ret < 0) {
		dprint(DBG_ON, "virtqueue_add_buf failed (%d)!\n", ret);
		spin_unlock(&vq->lock);
		return ret;
	}
	virtqueue_kick(vq->vq);
	spin_unlock_irqrestore(&vq->lock, flags);

	return 0;
}

void virtio_hyv_destroy_event_queue(struct virtio_hyv *vg)
{
	free_page((unsigned long)vg->evt_queue);
}

// sync with drivers/virtio/virtio_ring.c (3.13)
struct vring_virtqueue
{
	struct virtqueue vq;
	struct vring vring;
	bool weak_barriers;
	bool broken;
	bool indirect;
	bool event;
	unsigned int free_head;
	unsigned int num_added;
	u16 last_used_idx;
	bool (*notify)(struct virtqueue *vq);
	void *data[];
};

struct add_device_work
{
	struct work_struct work;
	struct virtio_hyv *vg;
	uint32_t host_handle;
};

static void add_device(struct work_struct *work)
{
	struct add_device_work *add_dev =
	    container_of(work, struct add_device_work, work);

	dprint(DBG_EVT, "host_handle: %u\n", add_dev->host_handle);

	if (register_hyv_device(add_dev->vg, add_dev->host_handle)) {
		dprint(DBG_ON, "register hyv device failed!\n");
	}
	kfree(add_dev);
}

struct rem_device_work
{
	struct work_struct work;
	uint32_t host_handle;
};

static int unregister_device(struct device *dev, void *data)
{
	uint32_t host_handle = (unsigned long)data;
	struct hyv_device *gdev = container_of(dev, struct hyv_device, dev);

	if (gdev->host_handle == host_handle) {
		unregister_hyv_device(gdev);
		return 1;
	}
	return 0;
}

static void rem_device(struct work_struct *work)
{
	struct rem_device_work *rem_dev =
	    container_of(work, struct rem_device_work, work);
	int ret;

	/* iterate through all device on bus and check for host handle */
	ret = hyv_bus_for_each_dev(&unregister_device,
				   (void *)(unsigned long)rem_dev->host_handle);

	if (!ret) {
		dprint(DBG_ON, "no device registered with this host id\n");
	}
	kfree(rem_dev);
}

void virtio_hyv_ack_event(struct virtqueue *vq)
{
	struct virtio_hyv *vg = vq->priv;
	struct vring_virtqueue *vvq =
	    container_of(vq, struct vring_virtqueue, vq);
	struct hyv_event event;
	unsigned long flags;

	dprint(DBG_EVT, "\n");

	spin_lock_irqsave(&vg->evt_lock, flags);
	while (LLQUEUE_POP(vg->evt_queue, vg->cback, event)) {
		spin_unlock_irqrestore(&vg->evt_lock, flags);
		switch (event.type) {
		case HYV_EVENT_CQ_COMP: {
			struct hyv_cq *cq = (struct hyv_cq *)event.id;

			dprint(DBG_EVT, "CQ_COMP\n");

			if (cq->ibcq.comp_handler) {
				cq->ibcq.comp_handler(&cq->ibcq,
						      cq->ibcq.cq_context);
			}
			break;
		}
		case HYV_EVENT_CQ: {
			struct ib_event ibevent;
			struct hyv_cq *cq = (struct hyv_cq *)event.id;

			dprint(DBG_EVT, "CQ\n");

			ibevent.device = cq->ibcq.device;
			ibevent.element.cq = &cq->ibcq;
			ibevent.event = event.ibevent;
			if (cq->ibcq.event_handler) {
				cq->ibcq.event_handler(&ibevent,
						       cq->ibcq.cq_context);
			}
			break;
		}
		case HYV_EVENT_QP: {
			struct ib_event ibevent;
			struct hyv_qp *qp = (struct hyv_qp *)event.id;

			dprint(DBG_EVT, "QP\n");

			ibevent.device = qp->ibqp.device;
			ibevent.element.qp = &qp->ibqp;
			ibevent.event = event.ibevent;
			if (qp->ibqp.event_handler) {
				qp->ibqp.event_handler(&ibevent,
						       qp->ibqp.qp_context);
			}
			break;
		}
		case HYV_EVENT_SRQ:
		case HYV_EVENT_ASYNC:
			dprint(DBG_ON, "SRQ/ASYNC\n");
			break;
		case HYV_EVENT_ADD_DEVICE: {
			struct add_device_work *work;

			dprint(DBG_EVT, "add device\n");

			work = kmalloc(sizeof(*work), GFP_ATOMIC);
			if (!work) {
				dprint(DBG_ON, "could not allocate work!\n");
				break;
			}
			INIT_WORK(&work->work, &add_device);
			work->vg = vg;
			work->host_handle = event.id;
			schedule_work(&work->work);
			break;
		}
		case HYV_EVENT_REM_DEVICE: {
			struct rem_device_work *work;

			dprint(DBG_EVT, "rem device\n");

			work = kmalloc(sizeof(*work), GFP_ATOMIC);
			if (!work) {
				dprint(DBG_ON, "could not allocate work!\n");
				break;
			}
			INIT_WORK(&work->work, &rem_device);
			work->host_handle = event.id;
			schedule_work(&work->work);
			break;
		}
		}
		spin_lock_irqsave(&vg->evt_lock, flags);
	}
	spin_unlock_irqrestore(&vg->evt_lock, flags);

	// XXX: let virtio believe there are new buffers
	vvq->num_added++;
}
