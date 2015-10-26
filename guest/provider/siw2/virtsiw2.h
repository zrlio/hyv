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

#ifndef VIRTSIW2_H_
#define VIRTSIW2_H_

#include <linux/device.h>
#include <rdma/ib_verbs.h>

#define VIRTSIW2_IB_UVERBS_ABI_VERSION 3

struct virtsiw2_device
{
	struct hyv_device *gdev;
	struct device dma_device;
};

struct virtsiw2_qp
{
	struct hyv_mmap *sq_mmap;
	struct hyv_mmap *rq_mmap;
};

struct virtsiw2_cq
{
	struct hyv_mmap *cq_mmap;
};

struct ib_cq *virtsiw2_create_cq(struct ib_device *ibdev, int entries,
				 int vector, struct ib_ucontext *ib_context,
				 struct ib_udata *udata);

int virtsiw2_destroy_cq(struct ib_cq *ib_cq);

struct ib_qp *virtsiw2_create_qp(struct ib_pd *ibpd,
				 struct ib_qp_init_attr *attr,
				 struct ib_udata *udata);

int virtsiw2_destroy_qp(struct ib_qp *ibqp);

int virtsiw2_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
		       struct ib_send_wr **bad_wr);

#endif /* VIRTSIW2_H_ */
