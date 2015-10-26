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

#ifndef VHOST_HYV_IBV_H_
#define VHOST_HYV_IBV_H_

#include <rdma/ib_verbs.h>

#include <object_map.h>

#define VHOST_HYV_MAGIC 0xDEADBEEF

struct vhost_hyv_ucontext
{
	struct object hdr;

	struct vhost_hyv_device *gdev;
	struct ib_ucontext *ibuctx;

	struct file *f;

	struct list_head mmaps;
	struct list_head pds;
	struct list_head cqs;

	struct vhost_hyv_umem **umem_map;
	unsigned int umem_map_size;
	spinlock_t umem_map_lock;
	struct list_head ibuctx_list;
};

void vhost_hyv_ucontext_release(struct object *obj);

struct vhost_hyv_pd
{
	struct object hdr;

	struct vhost_hyv_ucontext *uctx;
	struct ib_pd *ibpd;
	struct ib_uobject ibuobj;

	struct list_head qps;
	struct list_head srqs;
	struct list_head mrs;
};

void vhost_hyv_pd_release(struct object *obj);

struct vhost_hyv_cq
{
	struct object hdr;

	struct vhost_hyv_ucontext *uctx;
	struct ib_cq *ibcq;
	struct ib_uobject ibuobj;
};

void vhost_hyv_cq_release(struct object *obj);

struct vhost_hyv_qp
{
	struct object hdr;

	struct vhost_hyv_pd *pd;
	struct ib_qp *ibqp;
	struct ib_uobject ibuobj;

	struct vhost_hyv_cq *send_cq;
	struct vhost_hyv_cq *recv_cq;
	struct vhost_hyv_srq *srq;
};

void vhost_hyv_qp_release(struct object *obj);

struct vhost_hyv_srq
{
	struct object hdr;

	struct vhost_hyv_pd *pd;
	struct ib_srq *ibsrq;
	struct ib_uobject ibuobj;
};

void vhost_hyv_srq_release(struct object *obj);

struct vhost_hyv_mr
{
	struct object hdr;

	struct vhost_hyv_pd *pd;
	struct ib_mr *ibmr;
	struct ib_uobject ibuobj;
};

void vhost_hyv_mr_release(struct object *obj);

#endif /* VHOST_HYV_IBV_H_ */
