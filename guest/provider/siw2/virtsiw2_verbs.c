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

#include <hyv.h>

#include "siw_user.h"

#include "virtsiw2_debug.h"
#include "virtsiw2.h"

struct ib_cq *virtsiw2_create_cq(struct ib_device *ibdev, int entries,
				 int vector, struct ib_ucontext *ibuctx,
				 struct ib_udata *udata)
{
	struct ib_cq *ibcq;
	struct virtsiw2_cq *vcq;
	struct siw_uresp_create_cq uresp;
	struct hyv_cq *gcq;
	int ret;

	dprint(DBG_IBV, "\n");

	BUG_ON(!ibuctx);

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

	vcq->cq_mmap = hyv_mmap_prepare(
	    ibuctx, PAGE_ALIGN(uresp.num_cqe * sizeof(struct siw_cqe) +
			       sizeof(struct siw_cq_ctrl)),
	    uresp.cq_key);
	if (IS_ERR(vcq->cq_mmap)) {
		dprint(DBG_ON, "could not prepare cq mmap\n");
		ret = PTR_RET(vcq->cq_mmap);
		goto fail_vcq;
	}

	return ibcq;
fail_vcq:
	kfree(vcq);
fail_create_cq:
	hyv_ibv_destroy_cq(ibcq);
fail:
	return ERR_PTR(ret);
}

int virtsiw2_destroy_cq(struct ib_cq *ibcq)
{
	struct hyv_cq *cq = ibcq_to_hyv(ibcq);
	struct virtsiw2_cq *vcq = cq->priv;
	struct ib_ucontext *ibuctx = ibcq->uobject->context;

	dprint(DBG_IBV, "\n");

	hyv_unmap(ibuctx, vcq->cq_mmap);

	hyv_ibv_destroy_cq(ibcq);

	kfree(vcq);
	return 0;
}

struct ib_qp *virtsiw2_create_qp(struct ib_pd *ibpd,
				 struct ib_qp_init_attr *attr,
				 struct ib_udata *udata)
{
	struct ib_qp *ibqp;
	struct ib_ucontext *ibuctx = ibpd->uobject->context;
	struct virtsiw2_qp *vqp;
	struct siw_uresp_create_qp uresp;
	struct hyv_qp *gqp;
	int ret;

	BUG_ON(attr->qp_type != IB_QPT_RC);
	BUG_ON(!udata);

	dprint(DBG_IBV, "\n");

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

	vqp->sq_mmap = hyv_mmap_prepare(
	    ibuctx, PAGE_ALIGN(uresp.num_sqe * sizeof(struct siw_sqe)),
	    uresp.sq_key);
	if (IS_ERR(vqp->sq_mmap)) {
		dprint(DBG_ON, "could not prepare sq mmap\n");
		ret = PTR_RET(vqp->sq_mmap);
		goto fail_vqp;
	}

	vqp->rq_mmap = hyv_mmap_prepare(
	    ibuctx, PAGE_ALIGN(uresp.num_rqe * sizeof(struct siw_rqe)),
	    uresp.rq_key);
	if (IS_ERR(vqp->rq_mmap)) {
		dprint(DBG_ON, "could not prepare rq mmap\n");
		ret = PTR_RET(vqp->rq_mmap);
		goto fail_sq_mmap;
	}

	return ibqp;
fail_sq_mmap:
	hyv_mmap_unprepare(ibuctx, vqp->sq_mmap);
fail_vqp:
	kfree(vqp);
fail_create_qp:
	hyv_ibv_destroy_qp(ibqp);
fail:
	return ERR_PTR(ret);
}

int virtsiw2_destroy_qp(struct ib_qp *ibqp)
{
	struct hyv_qp *qp = ibqp_to_hyv(ibqp);
	struct virtsiw2_qp *vqp = qp->priv;
	struct ib_ucontext *ibuctx = ibqp->uobject->context;

	dprint(DBG_IBV, "\n");

	hyv_unmap(ibuctx, vqp->sq_mmap);
	hyv_unmap(ibuctx, vqp->rq_mmap);

	hyv_ibv_destroy_qp(ibqp);

	kfree(vqp);
	return 0;
}

int virtsiw2_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
		       struct ib_send_wr **bad_wr)
{
	return hyv_ibv_post_send_null(ibqp);
}
