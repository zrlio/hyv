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

#ifndef VIRTMLX4_H_
#define VIRTMLX4_H_

#include <linux/device.h>
#include <rdma/ib_verbs.h>

#define VIRTMLX4_IB_UVERBS_ABI_VERSION 3

struct virtmlx4_device
{
	struct hyv_device *gdev;
	struct device dma_device;
};

struct virtmlx4_ucontext
{
	struct hyv_mmap *uar_mmap;
	struct hyv_mmap *bf_mmap;
};

struct ib_cq *virtmlx4_create_cq(struct ib_device *ibdev, int entries,
				 int vector, struct ib_ucontext *ib_context,
				 struct ib_udata *udata);

struct ib_qp *virtmlx4_create_qp(struct ib_pd *ibpd,
				 struct ib_qp_init_attr *attr,
				 struct ib_udata *udata);

struct ib_srq *virtmlx4_create_srq(struct ib_pd *ibpd,
				   struct ib_srq_init_attr *attr,
				   struct ib_udata *udata);

#endif /* VIRTMLX4_H_ */
