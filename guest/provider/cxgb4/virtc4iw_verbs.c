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

#include <linux/slab.h>
#include <rdma/ib_verbs.h>
#include <linux/types.h>

#include <hyv.h>

#include "user.h"
#include "virtc4iw_debug.h"

#include "virtc4iw.h"

struct ib_ah *virtc4iw_ah_create(struct ib_pd *pd, struct ib_ah_attr *ah_attr)
{
	return ERR_PTR(-ENOSYS);
}

int virtc4iw_ah_destroy(struct ib_ah *ah)
{
	return -ENOSYS;
}

struct ib_pd *virtc4iw_alloc_pd(struct ib_device *ibdev,
				struct ib_ucontext *ibuctx,
				struct ib_udata *udata)
{
	if (udata) {
		return hyv_ibv_alloc_pd(ibdev, ibuctx, udata);
	} else {
		return ERR_PTR(-ENOSYS);
	}
}

struct ib_cq *virtc4iw_create_cq(struct ib_device *ibdev, int entries,
				 int vector, struct ib_ucontext *ibuctx,
				 struct ib_udata *udata)
{
	struct ib_cq *ibcq;
	struct virtc4iw_cq *vcq;
	struct c4iw_create_cq_resp uresp;
	struct hyv_cq *gcq;
	int ret;

	dprint(DBG_IBV, "\n");

	if (!ibuctx) {
        ret = -ENOSYS;
        goto fail;
    }

    ibcq = hyv_ibv_create_cq(ibdev, entries, vector, ibuctx, udata);
    if (IS_ERR(ibcq)) {
        ret = PTR_ERR(ibcq);
        goto fail;
    }

    if (copy_from_user(&uresp, udata->outbuf, sizeof(uresp))) {
        dprint(DBG_ON, "copy from udata failed\n");
        ret = -EFAULT;
        goto fail_create_cq;
    }

    vcq = kmalloc(sizeof(*vcq), GFP_KERNEL);
    if (!vcq) {
        dprint(DBG_ON, "could not allocate vcq\n");
        ret = -ENOMEM;
        goto fail_create_cq;
    }
    gcq = ibcq_to_hyv(ibcq);
    gcq->priv = vcq;

    vcq->cq_mmap =
        hyv_mmap_prepare(ibuctx, uresp.memsize, uresp.key);
    if (IS_ERR(vcq->cq_mmap)) {
        dprint(DBG_ON, "could not prepare cq mmap\n");
        ret = PTR_RET(vcq->cq_mmap);
        goto fail_vcq;
    }

    vcq->gts_mmap =
        hyv_mmap_prepare(ibuctx, PAGE_SIZE, uresp.gts_key);
    if (IS_ERR(vcq->gts_mmap)) {
        dprint(DBG_ON, "could not prepare cq mmap\n");
        ret = PTR_RET(vcq->gts_mmap);
        goto fail_cq_mmap;
    }

	return ibcq;
fail_cq_mmap:
	hyv_mmap_unprepare(ibuctx, vcq->cq_mmap);
fail_vcq:
	kfree(vcq);
fail_create_cq:
	hyv_ibv_destroy_cq(ibcq);
fail:
	return ERR_PTR(ret);
}

int virtc4iw_destroy_cq(struct ib_cq *ibcq)
{
	struct hyv_cq *cq = ibcq_to_hyv(ibcq);
	struct virtc4iw_cq *vcq = cq->priv;
	struct ib_ucontext *ibuctx;

	dprint(DBG_IBV, "\n");

    ibuctx = ibcq->uobject->context;

	hyv_unmap(ibuctx, vcq->cq_mmap);
	hyv_unmap(ibuctx, vcq->gts_mmap);

	hyv_ibv_destroy_cq(ibcq);

	kfree(vcq);
	return 0;
}

struct ib_qp *virtc4iw_create_qp(struct ib_pd *ibpd,
				 struct ib_qp_init_attr *attr,
				 struct ib_udata *udata)
{
	struct ib_qp *ibqp;
	struct ib_ucontext *ibuctx;
	struct virtc4iw_qp *vqp;
	struct c4iw_create_qp_resp uresp;
	struct hyv_qp *gqp;
	int ret;

	BUG_ON(attr->qp_type != IB_QPT_RC);

	dprint(DBG_IBV, "\n");

	if (!udata) {
        ret = -ENOSYS;
        goto fail;
    }
    ibuctx = ibpd->uobject->context;

    ibqp = hyv_ibv_create_qp(ibpd, attr, udata);
    if (IS_ERR(ibqp)) {
        ret = PTR_ERR(ibqp);
        goto fail;
    }

    if (copy_from_user(&uresp, udata->outbuf, sizeof(uresp))) {
        dprint(DBG_ON, "copy from udata failed\n");
        ret = -EFAULT;
        goto fail_create_qp;
    }

    vqp = kmalloc(sizeof(*vqp), GFP_KERNEL);
    if (!vqp) {
        dprint(DBG_ON, "could not allocate vqp\n");
        ret = -ENOMEM;
        goto fail_create_qp;
    }
    gqp = ibqp_to_hyv(ibqp);
    gqp->priv = vqp;

    vqp->sq_mmap =
        hyv_mmap_prepare(ibuctx, uresp.sq_memsize, uresp.sq_key);
    if (IS_ERR(vqp->sq_mmap)) {
        dprint(DBG_ON, "could not prepare sq mmap\n");
        ret = PTR_RET(vqp->sq_mmap);
        goto fail_vqp;
    }

    vqp->sq_db_gts_mmap =
        hyv_mmap_prepare(ibuctx, PAGE_SIZE, uresp.sq_db_gts_key);
    if (IS_ERR(vqp->sq_db_gts_mmap)) {
        dprint(DBG_ON, "could not prepare sq db gts mmap\n");
        ret = PTR_RET(vqp->sq_db_gts_mmap);
        goto fail_sq_mmap;
    }

    vqp->rq_mmap =
        hyv_mmap_prepare(ibuctx, uresp.rq_memsize, uresp.rq_key);
    if (IS_ERR(vqp->rq_mmap)) {
        dprint(DBG_ON, "could not prepare rq mmap\n");
        ret = PTR_RET(vqp->rq_mmap);
        goto fail_sq_db_gts_mmap;
    }

    vqp->rq_db_gts_mmap =
        hyv_mmap_prepare(ibuctx, PAGE_SIZE, uresp.rq_db_gts_key);
    if (IS_ERR(vqp->rq_db_gts_mmap)) {
        dprint(DBG_ON, "could not prepare rq db gts mmap\n");
        ret = PTR_RET(vqp->rq_db_gts_mmap);
        goto fail_rq_mmap;
    }

    if (uresp.flags & C4IW_QPF_ONCHIP) {
        vqp->ma_sync_mmap = hyv_mmap_prepare(ibuctx, PAGE_SIZE,
                             uresp.ma_sync_key);
        if (IS_ERR(vqp->ma_sync_mmap)) {
            dprint(DBG_ON,
                   "could not prepare rq db gts mmap\n");
            ret = PTR_RET(vqp->ma_sync_mmap);
            goto fail_rq_db_gts_mmap;
        }
    } else {
        dprint(DBG_ON, "sq not on chip!\n");
        vqp->ma_sync_mmap = NULL;
    }

	return ibqp;
fail_rq_db_gts_mmap:
	hyv_mmap_unprepare(ibuctx, vqp->rq_db_gts_mmap);
fail_rq_mmap:
	hyv_mmap_unprepare(ibuctx, vqp->rq_mmap);
fail_sq_db_gts_mmap:
	hyv_mmap_unprepare(ibuctx, vqp->sq_db_gts_mmap);
fail_sq_mmap:
	hyv_mmap_unprepare(ibuctx, vqp->sq_mmap);
fail_vqp:
	kfree(vqp);
fail_create_qp:
	hyv_ibv_destroy_qp(ibqp);
fail:
	return ERR_PTR(ret);
}

int virtc4iw_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *ibattr,
		       int attr_mask, struct ib_udata *udata)
{
	if (udata) {
		return hyv_ibv_modify_qp(ibqp, ibattr, attr_mask, udata);
	} else {
		return -ENOSYS;
	}
}

int virtc4iw_destroy_qp(struct ib_qp *ibqp)
{
	struct hyv_qp *qp = ibqp_to_hyv(ibqp);
	struct virtc4iw_qp *vqp = qp->priv;
	struct ib_ucontext *ibuctx;

	dprint(DBG_IBV, "\n");

    ibuctx = ibqp->uobject->context;

    hyv_unmap(ibuctx, vqp->sq_mmap);
	hyv_unmap(ibuctx, vqp->sq_db_gts_mmap);
	hyv_unmap(ibuctx, vqp->rq_mmap);
	hyv_unmap(ibuctx, vqp->rq_db_gts_mmap);
	if (vqp->ma_sync_mmap) {
		hyv_unmap(ibuctx, vqp->ma_sync_mmap);
	}

	hyv_ibv_destroy_qp(ibqp);

	kfree(vqp);
	return 0;
}

struct ib_mr *virtc4iw_reg_user_mr(struct ib_pd *ibpd, u64 user_va, u64 size,
				   u64 io_va, int access,
				   struct ib_udata *udata)
{
	struct hyv_udata_gvm udata_gvm;
	unsigned long pbl_depth;

	pbl_depth = size / PAGE_SIZE;
	if (size & ~PAGE_MASK)
		pbl_depth++;
	if (user_va & ~PAGE_MASK)
		pbl_depth++;
	udata_gvm.size = pbl_depth * sizeof(uint64_t);
	udata_gvm.udata_offset = 0;
	udata_gvm.mask = ~0UL;
	udata_gvm.type = HYV_COPY_TO_GUEST;

	return hyv_ibv_reg_user_mr_gv2hv(ibpd, user_va, size, io_va, access,
					 udata, &udata_gvm, 1);
}
