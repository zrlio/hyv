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

#ifndef VIRTC4IW_H_
#define VIRTC4IW_H_

#include <linux/device.h>
#include <rdma/ib_verbs.h>

#define VIRTC4IW_UVERBS_ABI_VERSION 5

struct hyv_device;

struct virtc4iw_device
{
	struct hyv_device *gdev;
	struct device dma_device;
};

/* VERBS */

struct virtc4iw_ucontext
{
	struct hyv_mmap *status_page_mmap;
};

struct virtc4iw_cq
{
	struct hyv_mmap *cq_mmap;
	struct hyv_mmap *gts_mmap;
};

struct virtc4iw_qp
{
	struct hyv_mmap *sq_mmap;
	struct hyv_mmap *sq_db_gts_mmap;
	struct hyv_mmap *rq_mmap;
	struct hyv_mmap *rq_db_gts_mmap;
	struct hyv_mmap *ma_sync_mmap;
};

struct ib_ah *virtc4iw_ah_create(struct ib_pd *pd, struct ib_ah_attr *ah_attr);

int virtc4iw_ah_destroy(struct ib_ah *ah);

struct ib_pd *virtc4iw_alloc_pd(struct ib_device *ibdev,
				struct ib_ucontext *ibuctx,
				struct ib_udata *udata);

struct ib_cq *virtc4iw_create_cq(struct ib_device *ibdev, int entries,
				 int vector, struct ib_ucontext *ib_context,
				 struct ib_udata *udata);

int virtc4iw_destroy_cq(struct ib_cq *ib_cq);

struct ib_qp *virtc4iw_create_qp(struct ib_pd *ibpd,
				 struct ib_qp_init_attr *attrs,
				 struct ib_udata *udata);

int virtc4iw_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *ibattr,
		       int attr_mask, struct ib_udata *udata);

int virtc4iw_destroy_qp(struct ib_qp *ibqp);

struct ib_mr *virtc4iw_reg_user_mr(struct ib_pd *ibpd, u64 user_va, u64 size,
				   u64 io_va, int access,
				   struct ib_udata *udata);

#endif /* VIRTC4IW_H_ */
