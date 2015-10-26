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

#include <hypercall_debug.h>
#include <hypercall_guest.h>

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#include <stdbool.h>

void hypercall_init_vq(struct hypercall_vq *hvq, struct virtqueue *vq)
{
	hvq->vq = vq;
	hvq->priv = vq->priv;
	// XXX: there is no nicer way for now
	vq->priv = hvq;
	spin_lock_init(&hvq->lock);
}

void hypercall_del_vq(struct hypercall_vq *hvq)
{
	hvq->vq->priv = hvq->priv;
}

void virtio_ack_hypercall(struct virtqueue *vq)
{
	struct hypercall_vq *hvq = vq->priv;
	unsigned long flags;
	unsigned int written;
	struct hypercall *hcall;

	dprint(DBG_GUEST, "\n");

	spin_lock_irqsave(&hvq->lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((hcall = virtqueue_get_buf(vq, &written)) != NULL) {
			spin_unlock_irqrestore(&hvq->lock, flags);
			if (hcall->async) {
				struct hypercall_async *hcall_async =
				    container_of(hcall, struct hypercall_async,
						 base);
				if (hcall_async->cb) {
					hcall_async->cbw(hvq, hcall_async);
				}
				kfree(hcall_async);
			} else {
				struct hypercall_sync *hcall_sync =
				    container_of(hcall, struct hypercall_sync,
						 base);
				complete(&hcall_sync->completion);
			}
			spin_lock_irqsave(&hvq->lock, flags);
		}
	} while (!virtqueue_enable_cb(vq));
	spin_unlock_irqrestore(&hvq->lock, flags);
}

int do_hypercall(struct hypercall_vq *hvq, const struct hypercall *hcall,
		 const struct hypercall_header *hdr, uint32_t copy_size,
		 const struct hypercall_parg *pargs, uint32_t npargs,
		 struct hypercall_ret_header *hret, uint32_t result_size)
{
	uint32_t i;
	int ret = 0;
	unsigned long irq_flags;
	uint32_t flags = hdr->flags;
	struct scatterlist *sgs[2];
	struct scatterlist sg[2 + HYPERCALL_MAX_PTR_ARGS];

	dprint(DBG_GUEST, "\n");

	sg_init_table(sg, 1 + npargs);
	sg_set_buf(&sg[0], hdr, copy_size);
	for (i = 0; i < npargs; i++) {
		sg_set_buf(&sg[i + 1], pargs[i].ptr, pargs[i].size);
	}
	sgs[0] = sg;

	sg_init_one(&sg[i + 1], hret, result_size);
	sgs[1] = &sg[i + 1];

	spin_lock_irqsave(&hvq->lock, irq_flags);
	ret = virtqueue_add_sgs(hvq->vq, sgs, 1, 1, (struct hypercall *)hcall,
				GFP_ATOMIC);
	if (ret < 0) {
		spin_unlock_irqrestore(&hvq->lock, irq_flags);
		return ret;
	}
	if (flags & HYPERCALL_NOTIFY_HOST) {
		virtqueue_kick(hvq->vq);
	}
	spin_unlock_irqrestore(&hvq->lock, irq_flags);

	return 0;
}

int do_hypercall_sync(struct hypercall_vq *hvq,
		      const struct hypercall_header *hdr, uint32_t copy_size,
		      const struct hypercall_parg *pargs, uint32_t npargs,
		      struct hypercall_ret_header *hret, uint32_t result_size)
{
	int ret;
	struct hypercall_sync hcall_sync = {
		{ false }, COMPLETION_INITIALIZER(hcall_sync.completion)
	};

	dprint(DBG_GUEST, "\n");

	ret = do_hypercall(hvq, &hcall_sync.base, hdr, copy_size, pargs, npargs,
			   hret, result_size);
	if (ret) {
		return ret;
	}

	wait_for_completion(&hcall_sync.completion);

	return 0;
}

int do_hypercall_async(struct hypercall_vq *hvq,
		       struct hypercall_async *hcall_async,
		       const struct hypercall_header *hdr, uint32_t copy_size,
		       uint32_t npargs, uint32_t result_size)
{
	hcall_async->base.async = true;

	dprint(DBG_GUEST, "\n");

	return do_hypercall(hvq, &hcall_async->base, hdr, copy_size,
			    hcall_async->pargs, npargs, hcall_async->hret,
			    result_size);
}
