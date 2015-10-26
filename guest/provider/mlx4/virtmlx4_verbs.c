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

#include <hyv.h>

#include <linux/mlx4/qp.h>
#include <linux/mlx4/srq.h>
#include <user.h>

#include "virtmlx4_debug.h"

#include "virtmlx4.h"

#define MLX4_CQ_ENTRY_SIZE 0x20

struct ib_cq *virtmlx4_create_cq(struct ib_device *ibdev, int entries,
				 int vector, struct ib_ucontext *ibuctx,
				 struct ib_udata *udata)
{
	struct ib_cq *ibcq;
	struct hyv_udata_gvm udata_gvm[2];
	struct mlx4_ib_create_cq ucmd;
	int ret;

	dprint(DBG_IBV, "\n");

	BUG_ON(!ibuctx);

	ret = ib_copy_from_udata(&ucmd, udata, sizeof(ucmd));
	if (ret) {
		dprint(DBG_ON, "copy from udata failed\n");
		goto fail;
	}

	entries = roundup_pow_of_two(entries + 1);

	udata_gvm[0].udata_offset =
	    offsetof(struct mlx4_ib_create_cq, buf_addr);
	udata_gvm[0].mask = ~0UL;
	udata_gvm[0].size = PAGE_ALIGN(MLX4_CQ_ENTRY_SIZE * entries);
	udata_gvm[0].type = HYV_IB_UMEM;

	udata_gvm[1].udata_offset = offsetof(struct mlx4_ib_create_cq, db_addr);
	udata_gvm[1].mask = PAGE_MASK;
	udata_gvm[1].size = PAGE_SIZE;
	udata_gvm[1].type = HYV_IB_UMEM;

	ibcq = hyv_ibv_create_cq_gv2hv(ibdev, entries, vector, ibuctx, udata,
				       udata_gvm, ARRAY_SIZE(udata_gvm));
	if (IS_ERR(ibcq)) {
		ret = PTR_ERR(ibcq);
		goto fail;
	}

	return ibcq;
fail:
	return ERR_PTR(ret);
}

struct ib_qp *virtmlx4_create_qp(struct ib_pd *ibpd,
				 struct ib_qp_init_attr *attr,
				 struct ib_udata *udata)
{
	struct ib_qp *ibqp;
	struct hyv_udata_gvm udata_gvm[2];
	unsigned int udata_gvm_cnt = 0;
	struct mlx4_ib_create_qp ucmd;
	unsigned long buf_size;
	unsigned long sq_wqe_cnt, sq_wqe_shift;
	unsigned long rq_wqe_cnt, rq_wqe_shift, rq_max_gs;
	int ret;

	dprint(DBG_IBV, "\n");

	BUG_ON(!udata);

	ret = ib_copy_from_udata(&ucmd, udata, sizeof(ucmd));
	if (ret) {
		dprint(DBG_ON, "copy from udata failed\n");
		goto fail;
	}

	sq_wqe_shift = ucmd.log_sq_stride;
	sq_wqe_cnt = 1 << ucmd.log_sq_bb_count;

	rq_wqe_cnt = roundup_pow_of_two(max(1U, attr->cap.max_recv_wr));
	rq_max_gs = roundup_pow_of_two(max(1U, attr->cap.max_recv_sge));
	rq_wqe_shift = ilog2(rq_max_gs * sizeof(struct mlx4_wqe_data_seg));

	buf_size = (sq_wqe_cnt << sq_wqe_shift) + (rq_wqe_cnt << rq_wqe_shift);

	udata_gvm[0].udata_offset =
	    offsetof(struct mlx4_ib_create_qp, buf_addr);
	udata_gvm[0].mask = ~0UL;
	udata_gvm[0].size = PAGE_ALIGN(buf_size);
	udata_gvm[0].type = HYV_IB_UMEM;
	udata_gvm_cnt++;

	if (!attr->srq) {
		udata_gvm[1].udata_offset =
		    offsetof(struct mlx4_ib_create_qp, db_addr);
		udata_gvm[1].mask = PAGE_MASK;
		udata_gvm[1].size = PAGE_SIZE;
		udata_gvm[1].type = HYV_IB_UMEM;
		udata_gvm_cnt++;
	}

	ibqp = hyv_ibv_create_qp_gv2hv(ibpd, attr, udata, udata_gvm,
				       udata_gvm_cnt);
	if (IS_ERR(ibqp)) {
		ret = PTR_ERR(ibqp);
		goto fail;
	}

	return ibqp;
fail:
	return ERR_PTR(ret);
}

struct ib_srq *virtmlx4_create_srq(struct ib_pd *ibpd,
				   struct ib_srq_init_attr *attr,
				   struct ib_udata *udata)
{
	struct ib_srq *ibsrq;
	struct hyv_udata_gvm udata_gvm[2];
	struct mlx4_ib_create_srq ucmd;
	unsigned long buf_size, desc_size, max, max_gs;
	int ret;

	dprint(DBG_IBV, "\n");

	BUG_ON(!udata);

	ret = ib_copy_from_udata(&ucmd, udata, sizeof(ucmd));
	if (ret) {
		dprint(DBG_ON, "copy from udata failed\n");
		goto fail;
	}

	max = roundup_pow_of_two(attr->attr.max_wr + 1);
	max_gs = attr->attr.max_sge;

	desc_size =
	    max(32UL,
		roundup_pow_of_two(sizeof(struct mlx4_wqe_srq_next_seg) +
				   max_gs * sizeof(struct mlx4_wqe_data_seg)));

	buf_size = max * desc_size;

	udata_gvm[0].udata_offset =
	    offsetof(struct mlx4_ib_create_srq, buf_addr);
	udata_gvm[0].mask = ~0UL;
	udata_gvm[0].size = PAGE_ALIGN(buf_size);
	udata_gvm[0].type = HYV_IB_UMEM;

	udata_gvm[1].udata_offset =
	    offsetof(struct mlx4_ib_create_srq, db_addr);
	udata_gvm[1].mask = PAGE_MASK;
	udata_gvm[1].size = PAGE_SIZE;
	udata_gvm[1].type = HYV_IB_UMEM;

	ibsrq = hyv_ibv_create_srq_gv2hv(ibpd, attr, udata, udata_gvm,
					 ARRAY_SIZE(udata_gvm));
	if (IS_ERR(ibsrq)) {
		ret = PTR_ERR(ibsrq);
		goto fail;
	}

	return ibsrq;
fail:
	return ERR_PTR(ret);
}
