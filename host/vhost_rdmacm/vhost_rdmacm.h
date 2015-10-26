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

#ifndef VHOST_RDMACM_H_
#define VHOST_RDMACM_H_

#include <linux/list.h>

#include <hypercall_host.h>
#include <rdmacm_hypercall.h>

#include <object_map.h>

struct vhost_rdmacm
{
	struct vhost_dev vdev;
	struct hypercall_vq vq;

	struct object_map ctxs;
};

static inline struct vhost_rdmacm *hvq_to_vcm(struct hypercall_vq *hvq)
{
	return container_of(hvq, struct vhost_rdmacm, vq);
}

struct vhost_rdmacm_event
{
	struct list_head list;
	struct hypercall_async *hcall_async;
	vrdmacm_event __user *event;
};

struct vhost_rdmacm_ctx
{
	struct object hdr;

	struct vhost_rdmacm *vcm;
	struct rdma_cm_id *id;

	struct list_head events;
};

void vhost_rdmacm_ctx_release(struct object *obj);

#endif /* VHOST_RDMACM_H_ */
