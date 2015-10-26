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

#include <linux/mm.h>
#include <linux/mman.h>
#include <rdma/ib_verbs.h>

#include <hypercall_host.h>
#include <hyv_hypercall.h>

#include <object_map.h>

#include "vhost_hyv.h"
#include "vhost_hyv_debug.h"
#include "vhost_hyv_dev.h"
#include "vhost_hyv_mem.h"
#include "vhost_hyv_event.h"

#include "vhost_hyv_ibv.h"

static void udata_to_ibudata(hyv_udata __user *udata, struct ib_udata *ibudata)
{
	// TODO check for size!!
	ibudata->inbuf = udata->data;
	ibudata->inlen = udata->in + sizeof(struct ib_uverbs_cmd_hdr);
	ibudata->outbuf = udata->data + udata->in;
	ibudata->outlen = udata->out;
}

/* match with guest hyv.h */
enum vhost_hyv_udata_gv2hv_type {
	VHOST_HYV_IB_UMEM,
	VHOST_HYV_COPY_FROM_GUEST,
	VHOST_HYV_COPY_TO_GUEST
};

static int udata_gv2hv_before(struct vhost_hyv_ucontext *uctx,
			      hyv_udata __user *udata,
			      hyv_udata_translate **udata_translate,
			      unsigned long udata_translate_size)
{
	hyv_udata_translate *ut;
	hyv_udata_translate *ut_iter;
	int ret;

	dprint(DBG_IBV, "\n");

	ut = kmalloc(udata_translate_size, GFP_KERNEL);
	if (!ut) {
		dprint(DBG_ON, "could not allocate udata translate\n");
		ret = -ENOMEM;
		goto fail;
	}

	if (copy_from_user(ut, *udata_translate, udata_translate_size)) {
		dprint(DBG_ON, "could not copy from user\n");
		ret = -EFAULT;
		goto fail_ut;
	}

	*udata_translate = ut;

	if (ut->n_chunks == 0) {
		return 0;
	}

	for (ut_iter = ut;
	     (void *)ut_iter < ((void *)ut) + udata_translate_size;
	     ut_iter =
		 (hyv_udata_translate *)&ut_iter->chunk[ut_iter->n_chunks]) {
		__u64 hva;

		if (copy_from_user(&hva, udata->data + ut_iter->udata_offset,
				   sizeof(hva))) {
			dprint(DBG_ON, "could not copy from user\n");
			ret = -EFAULT;
			goto fail_prepare;
		}

		switch (ut_iter->type) {
		case VHOST_HYV_IB_UMEM: {
			struct vhost_hyv_umem **umem;

			dprint(DBG_IBV, "prepare ib umem\n");

			umem = vhost_hyv_ib_umem_prepare(
			    uctx, hva, ut_iter->chunk, ut_iter->n_chunks);
			if (IS_ERR(umem)) {
				dprint(DBG_ON, "could not prepare umem\n");
				ret = PTR_ERR(umem);
				goto fail_prepare;
			}
			break;
		}
		case VHOST_HYV_COPY_TO_GUEST:
		case VHOST_HYV_COPY_FROM_GUEST: {
			unsigned int i;
			unsigned long size = 0;

			for (i = 0; i < ut_iter->n_chunks; i++) {
				size += ut_iter->chunk[i].size;
			}

			hva = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
				      MAP_SHARED | MAP_ANONYMOUS, 0);
			if (IS_ERR_VALUE(hva)) {
				dprint(DBG_ON, "could not mmap\n");
				ret = -ENOMEM;
				goto fail_prepare;
			}

			if (ut_iter->type == VHOST_HYV_COPY_FROM_GUEST) {
				unsigned long cur_hva = hva;
				for (i = 0; i < ut_iter->n_chunks; i++) {
					if (copy_from_user(
						(void *)cur_hva,
						(void *)ut_iter->chunk[i].addr,
						ut_iter->chunk[i].size)) {
						dprint(DBG_ON, "could not copy "
							       "from user\n");
						ret = -EFAULT;
						vm_munmap(hva, size);
						goto fail_prepare;
					}
					cur_hva += ut_iter->chunk[i].size;
				}
			}

			if (copy_to_user(udata->data + ut_iter->udata_offset,
					 &hva, sizeof(hva))) {
				dprint(DBG_ON, "could not copy to user\n");
				ret = -EFAULT;
				goto fail_prepare;
			}
			break;
		}
		default:
			/* unknown type */
			dprint(DBG_ON, "type unknown\n");
			break;
		}
	}

	return 0;
fail_prepare:
// TODO
fail_ut:
	kfree(ut);
fail:
	return ret;
}

static void udata_gv2hv_after(struct vhost_hyv_ucontext *uctx,
			      hyv_udata __user *udata,
			      hyv_udata_translate *udata_translate,
			      unsigned long udata_translate_size)
{
	hyv_udata_translate *ut = udata_translate;
	hyv_udata_translate *ut_iter;

	if (ut->n_chunks == 0) {
		kfree(ut);
		return;
	}

	for (ut_iter = ut;
	     (void *)ut_iter < ((void *)ut) + udata_translate_size;
	     ut_iter =
		 (hyv_udata_translate *)&ut_iter->chunk[ut_iter->n_chunks]) {
		__u64 hva;

		if (copy_from_user(&hva, udata->data + ut_iter->udata_offset,
				   sizeof(hva))) {
			dprint(DBG_ON, "could not copy from user\n");
			continue;
		}

		switch (ut_iter->type) {
		case VHOST_HYV_IB_UMEM: {
			if (vhost_hyv_ib_umem_finish_hva(uctx, hva)) {
				dprint(DBG_ON, "umem finish error\n");
			}
			break;
		}
		case VHOST_HYV_COPY_FROM_GUEST:
		case VHOST_HYV_COPY_TO_GUEST: {
			unsigned int i;
			unsigned long size = 0;

			for (i = 0; i < ut_iter->n_chunks; i++) {
				size += ut_iter->chunk[i].size;
			}

			if (current->mm) {
				if (ut_iter->type == VHOST_HYV_COPY_TO_GUEST) {
					unsigned long cur_hva = hva;
					for (i = 0; i < ut_iter->n_chunks;
					     i++) {
						if (copy_to_user(
							(void *)
							ut_iter->chunk[i].addr,
							(void *)cur_hva,
							ut_iter->chunk[i]
							    .size)) {
							dprint(DBG_ON,
							       "could not copy "
							       "to user\n");
							break;
						}
						cur_hva +=
						    ut_iter->chunk[i].size;
					}
				}
				vm_munmap(hva, size);
			}
			break;
		}
		default:
			/* unknown type */
			dprint(DBG_ON, "type unknown\n");
			break;
		}
	}

	kfree(ut);
}

DEF_HYPERCALL(hyv_ibv_query_deviceX, __s32, QUERY_DEV_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_device *gdev;
	struct ib_device *ibdev;
	struct ib_device_attr ibattr;
	hyv_query_device_result attr_tmp;
	int ret = 0;

	dprint(DBG_IBV, "\n");

	gdev = object_map_id_get_entry(&vg->devices, struct vhost_hyv_device,
				       hdr, dev_handle);
	if (!gdev) {
		ret = -EINVAL;
		goto fail;
	}
	ibdev = gdev->ibdev;

	ret = ib_query_device(ibdev, &ibattr);
	if (ret) {
		goto fail_id_get;
	}

	/* TODO: filter driver _here_ */

	attr_tmp.fw_ver = ibattr.fw_ver;
	attr_tmp.node_guid = ibdev->node_guid;
	attr_tmp.sys_image_guid = ibattr.sys_image_guid;
	attr_tmp.max_mr_size = ibattr.max_mr_size;
	attr_tmp.page_size_cap = ibattr.page_size_cap;
	attr_tmp.vendor_id = ibattr.vendor_id;
	attr_tmp.vendor_part_id = ibattr.vendor_part_id;
	attr_tmp.hw_ver = ibattr.hw_ver;
	attr_tmp.max_qp = ibattr.max_qp;
	attr_tmp.max_qp_wr = ibattr.max_qp_wr;
	attr_tmp.device_cap_flags = ibattr.device_cap_flags;
	attr_tmp.max_sge = ibattr.max_sge;
	attr_tmp.max_sge_rd = ibattr.max_sge_rd;
	attr_tmp.max_cq = ibattr.max_cq;
	attr_tmp.max_cqe = ibattr.max_cqe;
	attr_tmp.max_mr = ibattr.max_mr;
	attr_tmp.max_pd = ibattr.max_pd;
	attr_tmp.max_qp_rd_atom = ibattr.max_qp_rd_atom;
	attr_tmp.max_ee_rd_atom = ibattr.max_ee_rd_atom;
	attr_tmp.max_res_rd_atom = ibattr.max_res_rd_atom;
	attr_tmp.max_qp_init_rd_atom = ibattr.max_qp_init_rd_atom;
	attr_tmp.max_ee_init_rd_atom = ibattr.max_ee_init_rd_atom;
	attr_tmp.atomic_cap = ibattr.atomic_cap;
	attr_tmp.max_ee = ibattr.max_ee;
	attr_tmp.max_rdd = ibattr.max_rdd;
	attr_tmp.max_mw = ibattr.max_mw;
	attr_tmp.max_raw_ipv6_qp = ibattr.max_raw_ipv6_qp;
	attr_tmp.max_raw_ethy_qp = ibattr.max_raw_ethy_qp;
	attr_tmp.max_mcast_grp = ibattr.max_mcast_grp;
	attr_tmp.max_mcast_qp_attach = ibattr.max_mcast_qp_attach;
	attr_tmp.max_total_mcast_qp_attach = ibattr.max_total_mcast_qp_attach;
	attr_tmp.max_ah = ibattr.max_ah;
	attr_tmp.max_fmr = ibattr.max_fmr;
	attr_tmp.max_map_per_fmr = ibattr.max_map_per_fmr;
	attr_tmp.max_srq = ibattr.max_srq;
	attr_tmp.max_srq_wr = ibattr.max_srq_wr;
	attr_tmp.max_srq_sge = ibattr.max_srq_sge;
	attr_tmp.max_pkeys = ibattr.max_pkeys;
	attr_tmp.local_ca_ack_delay = ibattr.local_ca_ack_delay;
	attr_tmp.phys_port_cnt = ibdev->phys_port_cnt;

	if (copy_to_user(attr, &attr_tmp, sizeof(*attr))) {
		dprint(DBG_ON, "copy to user failed!\n");
		ret = -EFAULT;
	}
fail_id_get:
	object_put(&gdev->hdr, &vhost_hyv_device_release);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_ibv_query_portX, __s32, QUERY_PORT_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_device *gdev;
	struct ib_device *ibdev;
	struct ib_port_attr ibattr;
	hyv_query_port_result attr_tmp;
	int ret = 0;

	dprint(DBG_IBV, "\n");

	gdev = object_map_id_get_entry(&vg->devices, struct vhost_hyv_device,
				       hdr, dev_handle);
	if (!gdev) {
		ret = -EINVAL;
		goto fail;
	}
	ibdev = gdev->ibdev;

	ret = ib_query_port(ibdev, port_num, &ibattr);
	if (ret) {
		goto fail_id_get;
	}

	/* TODO: filter driver _here_ */

	attr_tmp.state = ibattr.state;
	attr_tmp.max_mtu = ibattr.max_mtu;
	attr_tmp.active_mtu = ibattr.active_mtu;
	attr_tmp.gid_tbl_len = ibattr.gid_tbl_len;
	attr_tmp.port_cap_flags = ibattr.port_cap_flags;
	attr_tmp.max_msg_sz = ibattr.max_msg_sz;
	attr_tmp.bad_pkey_cntr = ibattr.bad_pkey_cntr;
	attr_tmp.qkey_viol_cntr = ibattr.qkey_viol_cntr;
	attr_tmp.pkey_tbl_len = ibattr.pkey_tbl_len;
	attr_tmp.lid = ibattr.lid;
	attr_tmp.sm_lid = ibattr.sm_lid;
	attr_tmp.lmc = ibattr.lmc;
	attr_tmp.max_vl_num = ibattr.max_vl_num;
	attr_tmp.sm_sl = ibattr.sm_sl;
	attr_tmp.subnet_timeout = ibattr.subnet_timeout;
	attr_tmp.init_type_reply = ibattr.init_type_reply;
	attr_tmp.active_width = ibattr.active_width;
	attr_tmp.active_speed = ibattr.active_speed;
	attr_tmp.phys_state = ibattr.phys_state;
	attr_tmp.link_layer = rdma_port_get_link_layer(ibdev, port_num);

	if (copy_to_user(attr, &attr_tmp, sizeof(*attr))) {
		dprint(DBG_ON, "copy to user failed!\n");
		ret = -EFAULT;
	}
fail_id_get:
	object_put(&gdev->hdr, &vhost_hyv_device_release);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_ibv_query_pkeyX, __s32, QUERY_PKEY_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_device *gdev;
	int ret;
	u16 pkey;

	gdev = object_map_id_get_entry(&vg->devices, struct vhost_hyv_device,
				       hdr, dev_handle);
	if (!gdev) {
		ret = -EINVAL;
		goto fail;
	}

	ret = ib_query_pkey(gdev->ibdev, port, index, &pkey);
	if (ret) {
		dprint(DBG_ON, "query pkey failed\n");
		goto fail_id_get;
	}
	ret = pkey;

fail_id_get:
	object_put(&gdev->hdr, &vhost_hyv_device_release);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_ibv_query_gidX, __s32, QUERY_GID_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_device *gdev;
	struct ib_device *ibdev;
	union ib_gid ibgid;
	int ret = 0;

	dprint(DBG_IBV, "\n");

	gdev = object_map_id_get_entry(&vg->devices, struct vhost_hyv_device,
				       hdr, dev_handle);
	if (!gdev) {
		ret = -EINVAL;
		goto fail;
	}
	ibdev = gdev->ibdev;

	ret = ib_query_gid(ibdev, port, index, &ibgid);
	if (ret) {
		goto fail_id_get;
	}

	if (copy_to_user(gid, &ibgid, sizeof(*gid))) {
		dprint(DBG_ON, "copy to user failed!\n");
		ret = -EFAULT;
	}

fail_id_get:
	object_put(&gdev->hdr, &vhost_hyv_device_release);
fail:
	return ret;
}

void vhost_hyv_ucontext_release(struct object *obj)
{
	struct vhost_hyv_ucontext *uctx =
	    container_of(obj, struct vhost_hyv_ucontext, hdr);
	struct vhost_hyv_mmap *mmap, *tmp_mmap;
	struct vhost_hyv_pd *pd, *tmp_pd;
	struct vhost_hyv_cq *cq, *tmp_cq;

	dprint(DBG_IBV, "\n");

	/* force release all mmaps */
	list_for_each_entry_safe(mmap, tmp_mmap, &uctx->mmaps, hdr.list)
	{
		dprint(DBG_ON, "unreleased mmap (0x%lx) -> force release\n",
		       mmap->hva);
		vhost_hyv_mmap_release(&mmap->hdr);
	}

	list_for_each_entry_safe(cq, tmp_cq, &uctx->cqs, hdr.list)
	{
		dprint(DBG_ON, "unreleased cq (%d) -> force release\n",
		       cq->hdr.id);
		vhost_hyv_mmap_release(&cq->hdr);
	}

	list_for_each_entry_safe(pd, tmp_pd, &uctx->pds, hdr.list)
	{
		dprint(DBG_ON, "unreleased pd (%d) -> force release\n",
		       pd->hdr.id);
		vhost_hyv_mmap_release(&pd->hdr);
	}

	uctx->gdev->ibdev->dealloc_ucontext(uctx->ibuctx);

	object_put(&uctx->gdev->hdr, &vhost_hyv_device_release);
	filp_close(uctx->f, NULL);
	kfree(uctx->umem_map);
	kfree(uctx);
}

DEF_HYPERCALL(hyv_ibv_alloc_ucontextX, __s32, ALLOC_UCTX_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_device *gdev;
	struct vhost_hyv_ucontext *uctx;
	struct ib_device *ibdev;
	struct ib_udata ibudata;
	struct ib_ucontext *ibuctx;
	int ret = 0;

	dprint(DBG_IBV, "\n");

	gdev = object_map_id_get_entry(&vg->devices, struct vhost_hyv_device,
				       hdr, dev_handle);
	if (!gdev) {
		ret = -EINVAL;
		goto fail;
	}
	ibdev = gdev->ibdev;

	udata_to_ibudata(udata, &ibudata);

	ibuctx = ibdev->alloc_ucontext(ibdev, &ibudata);
	if (IS_ERR(ibuctx)) {
		ret = PTR_ERR(ibuctx);
		goto fail_id_get;
	}
	ibuctx->device = ibdev;
	ibuctx->closing = VHOST_HYV_MAGIC;
	INIT_LIST_HEAD(&ibuctx->rule_list);

	uctx = kmalloc(sizeof(*uctx), GFP_KERNEL);
	if (!uctx) {
		dprint(DBG_ON, "allocating ucontext failed!\n");
		goto fail_alloc_uctx;
	}
	uctx->ibuctx = ibuctx;
	uctx->gdev = gdev;
	INIT_LIST_HEAD(&uctx->mmaps);
	INIT_LIST_HEAD(&uctx->pds);
	INIT_LIST_HEAD(&uctx->cqs);
	list_add(&uctx->ibuctx_list, &ibuctx->rule_list);
	uctx->umem_map_size = 128;
	uctx->umem_map = kmalloc(sizeof(*uctx->umem_map) * uctx->umem_map_size,
				 GFP_KERNEL | __GFP_ZERO);
	if (!uctx->umem_map) {
		dprint(DBG_ON, "could not alloc umem map\n");
		ret = -ENOMEM;
		goto fail_uctx;
	}
	spin_lock_init(&uctx->umem_map_lock);

	uctx->f = filp_open("/dev/vhost-hyv-mmap", O_RDONLY, 0);
	if (IS_ERR(uctx->f)) {
		dprint(DBG_ON, "could not open file!\n");
		goto fail_umem_map;
	}
	uctx->f->private_data = ibuctx;

	ret = object_map_add(&vg->uctxs, &gdev->uctxs, &uctx->hdr);
	if (ret < 0) {
		goto fail_open;
	}

	return ret;
fail_open:
	filp_close(uctx->f, NULL);
fail_umem_map:
	kfree(uctx->umem_map);
fail_uctx:
	kfree(uctx);
fail_alloc_uctx:
	ibdev->dealloc_ucontext(ibuctx);
fail_id_get:
	object_put(&gdev->hdr, &vhost_hyv_device_release);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_ibv_dealloc_ucontextX, __s32, DEALLOC_UCTX_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);

	dprint(DBG_IBV, "\n");

	return object_map_id_del(&vg->uctxs, uctx_handle,
				 &vhost_hyv_ucontext_release);
}

void vhost_hyv_pd_release(struct object *obj)
{
	struct vhost_hyv_pd *pd = container_of(obj, struct vhost_hyv_pd, hdr);
	struct ib_device *ibdev = pd->ibpd->device;
	struct vhost_hyv_qp *qp, *tmp_qp;
	struct vhost_hyv_srq *srq, *tmp_srq;
	struct vhost_hyv_mr *mr, *tmp_mr;

	dprint(DBG_IBV, "\n");

	/* force release qps */
	list_for_each_entry_safe(qp, tmp_qp, &pd->qps, hdr.list)
	{
		dprint(DBG_ON, "unreleased qp (%d) -> force release\n",
		       qp->ibqp->qp_num);
		vhost_hyv_qp_release(&qp->hdr);
	}

	/* force release srqs */
	list_for_each_entry_safe(srq, tmp_srq, &pd->srqs, hdr.list)
	{
		dprint(DBG_ON, "unreleased srq -> force release\n");
		vhost_hyv_srq_release(&srq->hdr);
	}

	/* force release mrs */
	list_for_each_entry_safe(mr, tmp_mr, &pd->mrs, hdr.list)
	{
		dprint(DBG_ON, "unreleased mr (%u/%u) -> force release\n",
		       mr->ibmr->lkey, mr->ibmr->rkey);
		vhost_hyv_mr_release(&mr->hdr);
	}

	ibdev->dealloc_pd(pd->ibpd);

	object_put(&pd->uctx->hdr, &vhost_hyv_ucontext_release);
	kfree(pd);
}

DEF_HYPERCALL(hyv_ibv_alloc_pdX, __s32, ALLOC_PD_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_ucontext *uctx;
	struct vhost_hyv_pd *pd;
	struct ib_device *ibdev;
	struct ib_udata ibudata;
	struct ib_pd *ibpd;
	int ret;

	dprint(DBG_IBV, "\n");

	uctx = object_map_id_get_entry(&vg->uctxs, struct vhost_hyv_ucontext,
				       hdr, uctx_handle);
	if (!uctx) {
		ret = -EINVAL;
		goto fail;
	}

	pd = kmalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd) {
		dprint(DBG_ON, "could not allocate pd\n");
		ret = -ENOMEM;
		goto fail_uctx;
	}
	pd->uctx = uctx;
	INIT_LIST_HEAD(&pd->qps);
	INIT_LIST_HEAD(&pd->srqs);
	INIT_LIST_HEAD(&pd->mrs);

	udata_to_ibudata(udata, &ibudata);

	ibdev = uctx->ibuctx->device;
	ibpd = ibdev->alloc_pd(ibdev, uctx->ibuctx, &ibudata);
	if (IS_ERR(ibpd)) {
		ret = PTR_ERR(ibpd);
		goto fail_pd;
	}
	pd->ibpd = ibpd;

	/* init ibpd to make providers happy */
	ibpd->device = ibdev;
	pd->ibuobj.context = uctx->ibuctx;
	ibpd->uobject = &pd->ibuobj;

	ret = object_map_add(&vg->pds, &uctx->pds, &pd->hdr);
	if (ret < 0) {
		goto fail_alloc;
	}

	return ret;
fail_alloc:
	ibdev->dealloc_pd(ibpd);
fail_pd:
	kfree(pd);
fail_uctx:
	object_put(&uctx->hdr, &vhost_hyv_ucontext_release);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_ibv_dealloc_pdX, __s32, DEALLOC_PD_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);

	dprint(DBG_IBV, "\n");

	return object_map_id_del(&vg->pds, pd_handle, &vhost_hyv_pd_release);
}

void vhost_hyv_cq_release(struct object *obj)
{
	struct vhost_hyv_cq *cq = container_of(obj, struct vhost_hyv_cq, hdr);
	struct ib_device *ibdev = cq->ibcq->device;
	void *cq_context;

	dprint(DBG_IBV, "\n");

	cq_context = cq->ibcq->cq_context;
	cq->ibcq->cq_context = NULL;
	kfree(cq_context);

	ibdev->destroy_cq(cq->ibcq);

	object_put(&cq->uctx->hdr, &vhost_hyv_ucontext_release);
	kfree(cq);
}

struct vhost_hyv_cq_context
{
	struct vhost_hyv *vg;
	u64 guest_handle;
};

static void vhost_hyv_comp_handler(struct ib_cq *cq, void *cq_context)
{
	struct vhost_hyv_cq_context *vcq_ctx;
	struct vhost_hyv *vg;
	struct hyv_event event;

	dprint(DBG_IBV, "\n");

	if (!cq_context) {
		dprint(DBG_ON, "context null\n");
		return;
	}

	vcq_ctx = cq_context;
	vg = vcq_ctx->vg;

	event.type = HYV_EVENT_CQ_COMP;
	event.id = vcq_ctx->guest_handle;
	event.port = 0;
	event.ibevent = 0;

	if (vhost_hyv_push_event(vg, event, true)) {
		dprint(DBG_ON, "push event failed!\n");
	}
}

static void vhost_hyv_cq_event_handler(struct ib_event *event, void *cq_context)
{
	struct vhost_hyv_cq_context *vcq_ctx;
	struct vhost_hyv *vg;
	struct hyv_event gevent;

	dprint(DBG_IBV, "\n");

	if (!cq_context) {
		dprint(DBG_ON, "context null\n");
		return;
	}

	if (event->event != IB_EVENT_CQ_ERR) {
		dprint(DBG_ON, "not a cq error!\n");
		return;
	}

	vcq_ctx = cq_context;
	vg = vcq_ctx->vg;

	gevent.type = HYV_EVENT_CQ;
	gevent.ibevent = event->event;
	gevent.id = vcq_ctx->guest_handle;
	gevent.port = 0;

	if (vhost_hyv_push_event(vg, gevent, true)) {
		dprint(DBG_ON, "push event failed!\n");
	}
}

DEF_HYPERCALL(hyv_ibv_create_cqX, hyv_create_cq_result, CREATE_CQ_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_ucontext *uctx;
	struct vhost_hyv_cq *cq;
	struct vhost_hyv_cq_context *vcq_ctx;
	struct ib_device *ibdev;
	struct ib_udata ibudata;
	struct ib_cq *ibcq;
	int ret;

	dprint(DBG_IBV, "\n");

	uctx = object_map_id_get_entry(&vg->uctxs, struct vhost_hyv_ucontext,
				       hdr, uctx_handle);
	if (!uctx) {
		ret = -EINVAL;
		goto fail;
	}

	cq = kmalloc(sizeof(*cq), GFP_KERNEL);
	if (!cq) {
		dprint(DBG_ON, "could not allocate cq\n");
		ret = -ENOMEM;
		goto fail_uctx;
	}
	cq->uctx = uctx;

	ret = udata_gv2hv_before(uctx, udata, &udata_translate,
				 udata_translate_size);
	if (ret) {
		dprint(DBG_ON, "could not translate udata\n");
		goto fail_cq;
	}

	udata_to_ibudata(udata, &ibudata);

	ibdev = uctx->ibuctx->device;
	ibcq = ibdev->create_cq(ibdev, entries, vector, uctx->ibuctx, &ibudata);
	if (IS_ERR(ibcq)) {
		ret = PTR_ERR(ibcq);
		dprint(DBG_ON, "could not create cq (%d)\n", ret);
		goto fail_udata;
	}
	cq->ibcq = ibcq;
	ibcq->device = ibdev;
	ibcq->comp_handler = &vhost_hyv_comp_handler;
	ibcq->event_handler = &vhost_hyv_cq_event_handler;

	udata_gv2hv_after(uctx, udata, udata_translate, udata_translate_size);

	vcq_ctx = kmalloc(sizeof(*vcq_ctx), GFP_KERNEL);
	if (!vcq_ctx) {
		dprint(DBG_ON, "could not allocate cq context!\n");
		ret = -ENOMEM;
		goto fail_create;
	}
	vcq_ctx->vg = vg;
	vcq_ctx->guest_handle = guest_handle;
	ibcq->cq_context = vcq_ctx;
	cq->ibuobj.context = uctx->ibuctx;
	ibcq->uobject = &cq->ibuobj;

	ret = object_map_add(&vg->cqs, &uctx->cqs, &cq->hdr);
	if (ret < 0) {
		goto fail_context;
	}

	return (hyv_create_cq_result) { ret, cq->ibcq->cqe };
fail_context:
	kfree(vcq_ctx);
fail_create:
	ibdev->destroy_cq(ibcq);
fail_udata:
	udata_gv2hv_after(uctx, udata, udata_translate, udata_translate_size);
fail_cq:
	kfree(cq);
fail_uctx:
	object_put(&uctx->hdr, &vhost_hyv_ucontext_release);
fail:
	return (hyv_create_cq_result) { ret, 0 };
}

DEF_HYPERCALL(hyv_ibv_destroy_cqX, __s32, DESTROY_CQ_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);

	dprint(DBG_IBV, "\n");

	return object_map_id_del(&vg->cqs, cq_handle, &vhost_hyv_cq_release);
}

struct vhost_hyv_qp_context
{
	struct vhost_hyv *vg;
	u64 guest_handle;
};

static void vhost_hyv_qp_event_handler(struct ib_event *event, void *qp_context)
{
	struct vhost_hyv_qp_context *vqp_ctx;
	struct vhost_hyv *vg;
	struct hyv_event gevent;

	dprint(DBG_IBV, "\n");

	if (!qp_context) {
		dprint(DBG_ON, "context null\n");
		return;
	}

	switch (event->event) {
	case IB_EVENT_QP_ACCESS_ERR:
	case IB_EVENT_QP_FATAL:
	case IB_EVENT_QP_LAST_WQE_REACHED:
	case IB_EVENT_QP_REQ_ERR:
		break;
	default:
		dprint(DBG_ON, "not a qp error!\n");
		return;
	}
	vqp_ctx = qp_context;
	vg = vqp_ctx->vg;

	gevent.type = HYV_EVENT_QP;
	gevent.ibevent = event->event;
	gevent.id = vqp_ctx->guest_handle;
	gevent.port = 0;

	if (vhost_hyv_push_event(vg, gevent, true)) {
		dprint(DBG_ON, "push event failed!\n");
	}
}

void vhost_hyv_qp_release(struct object *obj)
{
	struct vhost_hyv_qp *qp = container_of(obj, struct vhost_hyv_qp, hdr);
	struct ib_device *ibdev = qp->ibqp->device;
	void *data = qp->ibqp->qp_context;

	dprint(DBG_IBV, "\n");

	qp->ibqp->qp_context = NULL;
	kfree(data);

	ibdev->destroy_qp(qp->ibqp);

	if (qp->srq) {
		object_put(&qp->srq->hdr, &vhost_hyv_srq_release);
	}
	object_put(&qp->recv_cq->hdr, &vhost_hyv_cq_release);
	object_put(&qp->send_cq->hdr, &vhost_hyv_cq_release);
	object_put(&qp->pd->hdr, &vhost_hyv_pd_release);
	kfree(qp);
}

DEF_HYPERCALL(hyv_ibv_create_qpX, __s32, CREATE_QP_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_pd *pd;
	struct vhost_hyv_qp *qp;
	struct ib_udata ibudata;
	struct ib_device *ibdev;
	struct ib_qp_init_attr attr;
	struct ib_qp *ibqp;
	struct vhost_hyv_cq *send_cq, *recv_cq;
	struct vhost_hyv_srq *srq = NULL;
	struct vhost_hyv_qp_context *vqp_ctx;
	hyv_create_qp_result res_tmp;
	int ret;

	dprint(DBG_IBV, "\n");

	pd = object_map_id_get_entry(&vg->pds, struct vhost_hyv_pd, hdr,
				     pd_handle);
	if (!pd) {
		ret = -EINVAL;
		goto fail;
	}

	BUG_ON(init_attr.qp_type != IB_QPT_RC);

	send_cq = object_map_id_get_entry(&vg->cqs, struct vhost_hyv_cq, hdr,
					  init_attr.send_cq_handle);
	if (!send_cq) {
		ret = -EINVAL;
		goto fail_pd;
	}

	recv_cq = object_map_id_get_entry(&vg->cqs, struct vhost_hyv_cq, hdr,
					  init_attr.recv_cq_handle);
	if (!recv_cq) {
		ret = -EINVAL;
		goto fail_send_cq;
	}

	if (init_attr.srq_handle >= 0) {
		srq = object_map_id_get_entry(&vg->srqs, struct vhost_hyv_srq,
					      hdr, init_attr.srq_handle);
		if (!srq) {
			ret = -EINVAL;
			goto fail_recv_cq;
		}
	}

	qp = kmalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		ret = -ENOMEM;
		goto fail_srq;
	}
	qp->pd = pd;
	qp->send_cq = send_cq;
	qp->recv_cq = recv_cq;
	qp->srq = srq;

	ret = udata_gv2hv_before(pd->uctx, udata, &udata_translate,
				 udata_translate_size);
	if (ret) {
		dprint(DBG_ON, "could not translate udata\n");
		goto fail_qp;
	}

	udata_to_ibudata(udata, &ibudata);

	vqp_ctx = kmalloc(sizeof(*vqp_ctx), GFP_KERNEL);
	if (!vqp_ctx) {
		dprint(DBG_ON, "could not allocate qp context!\n");
		ret = -ENOMEM;
		goto fail_udata;
	}
	vqp_ctx->vg = vg;
	vqp_ctx->guest_handle = guest_handle;

	attr.qp_context = vqp_ctx;
	attr.event_handler = &vhost_hyv_qp_event_handler;
	attr.send_cq = send_cq->ibcq;
	attr.recv_cq = recv_cq->ibcq;
	attr.srq = srq ? srq->ibsrq : NULL;
	attr.xrcd = NULL;
	attr.sq_sig_type = init_attr.sq_sig_type;
	attr.qp_type = init_attr.qp_type;
	attr.create_flags = init_attr.create_flags;
	attr.port_num = init_attr.port_num;

	copy_hyv_qp_cap_to_ib(&init_attr.cap, &attr.cap);

	ibdev = pd->ibpd->device;
	ibqp = ibdev->create_qp(pd->ibpd, &attr, &ibudata);
	if (IS_ERR(ibqp)) {
		ret = PTR_ERR(ibqp);
		dprint(DBG_ON, "create_qp failed (%d)\n", ret);
		goto fail_context;
	}
	qp->ibqp = ibqp;
	qp->ibuobj.context = pd->uctx->ibuctx;
	ibqp->uobject = &qp->ibuobj;
	ibqp->device = ibdev;
	ibqp->pd = pd->ibpd;
	ibqp->recv_cq = recv_cq->ibcq;
	ibqp->send_cq = send_cq->ibcq;
	ibqp->srq = srq ? srq->ibsrq : NULL;
	ibqp->qp_type = init_attr.qp_type;
	ibqp->qp_context = vqp_ctx;
	ibqp->event_handler = &vhost_hyv_qp_event_handler;
	ibqp->real_qp = ibqp;

	udata_gv2hv_after(pd->uctx, udata, udata_translate,
			  udata_translate_size);

	ret = object_map_add(&vg->qps, &pd->qps, &qp->hdr);
	if (ret < 0) {
		goto fail_create;
	}

	res_tmp.qp_handle = ret;
	res_tmp.qpn = ibqp->qp_num;
	copy_ib_qp_cap_to_hyv(&attr.cap, &res_tmp.cap);

	if (copy_to_user(res, &res_tmp, res_size)) {
		dprint(DBG_ON, "could not copy to user\n");
		ret = -EFAULT;
		goto fail_create;
	}

	return 0;
fail_create:
	ibdev->destroy_qp(ibqp);
fail_context:
	kfree(vqp_ctx);
fail_udata:
	udata_gv2hv_after(pd->uctx, udata, udata_translate,
			  udata_translate_size);
fail_qp:
	kfree(qp);
fail_srq:
	if (srq) {
		object_put(&srq->hdr, &vhost_hyv_srq_release);
	}
fail_recv_cq:
	object_put(&recv_cq->hdr, &vhost_hyv_cq_release);
fail_send_cq:
	object_put(&send_cq->hdr, &vhost_hyv_cq_release);
fail_pd:
	object_put(&pd->hdr, &vhost_hyv_pd_release);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_ibv_modify_qpX, __s32, MODIFY_QP_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_qp *qp;
	struct ib_qp_attr ibattr;
	struct ib_udata ibudata;
	int ret;

	dprint(DBG_IBV, "\n");

	qp = object_map_id_get_entry(&vg->qps, struct vhost_hyv_qp, hdr,
				     qp_handle);
	if (!qp) {
		ret = -EINVAL;
		goto fail;
	}

	copy_hyv_qp_attr_to_ib(&attr, &ibattr);

	udata_to_ibudata(udata, &ibudata);

	ret =
	    qp->ibqp->device->modify_qp(qp->ibqp, &ibattr, attr_mask, &ibudata);

	object_put(&qp->hdr, &vhost_hyv_qp_release);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_ibv_query_qpX, __s32, QUERY_QP_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_qp *qp;
	struct ib_qp_attr ibattr;
	struct ib_qp_init_attr ibinit_attr;
	hyv_qp_attr tmp_attr;
	hyv_qp_init_attr tmp_init_attr;
	int ret = 0;

	dprint(DBG_IBV, "\n");

	qp = object_map_id_get_entry(&vg->qps, struct vhost_hyv_qp, hdr,
				     qp_handle);
	if (!qp) {
		ret = -EINVAL;
		goto fail;
	}

	ret = qp->ibqp->device->query_qp(qp->ibqp, &ibattr, attr_mask,
					 &ibinit_attr);
	if (ret) {
		dprint(DBG_ON, "could not query qp\n");
		goto fail_qp;
	}

	copy_ib_qp_attr_to_hyv(&ibattr, &tmp_attr);
	copy_ib_qp_cap_to_hyv(&ibinit_attr.cap, &tmp_init_attr.cap);
	tmp_init_attr.create_flags = ibinit_attr.create_flags;
	tmp_init_attr.sq_sig_type = ibinit_attr.sq_sig_type;

	if (copy_to_user(attr, &tmp_attr, attr_size)) {
		dprint(DBG_ON, "could not copy attr to user\n");
		ret = -EFAULT;
		goto fail_qp;
	}

	if (copy_to_user(init_attr, &tmp_init_attr, init_attr_size)) {
		dprint(DBG_ON, "could not copy init attr to user\n");
		ret = -EFAULT;
		goto fail_qp;
	}

fail_qp:
	object_put(&qp->hdr, &vhost_hyv_qp_release);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_ibv_destroy_qpX, __s32, DESTROY_QP_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);

	dprint(DBG_IBV, "\n");

	return object_map_id_del(&vg->qps, qp_handle, &vhost_hyv_qp_release);
}

struct vhost_hyv_srq_context
{
	struct vhost_hyv *vg;
	u64 guest_handle;
};

static void vhost_hyv_srq_event_handler(struct ib_event *event,
					void *srq_context)
{
	struct vhost_hyv_srq_context *vsrq_ctx;
	struct vhost_hyv *vg;
	struct hyv_event gevent;

	dprint(DBG_IBV, "\n");

	if (!srq_context) {
		dprint(DBG_ON, "context null\n");
		return;
	}

	switch (event->event) {
	case IB_EVENT_SRQ_ERR:
	case IB_EVENT_SRQ_LIMIT_REACHED:
		break;
	default:
		dprint(DBG_ON, "not a srq error!\n");
		return;
	}
	vsrq_ctx = srq_context;
	vg = vsrq_ctx->vg;

	gevent.type = HYV_EVENT_SRQ;
	gevent.ibevent = event->event;
	gevent.id = vsrq_ctx->guest_handle;
	gevent.port = 0;

	if (vhost_hyv_push_event(vg, gevent, true)) {
		dprint(DBG_ON, "push event failed!\n");
	}
}

void vhost_hyv_srq_release(struct object *obj)
{
	struct vhost_hyv_srq *srq =
	    container_of(obj, struct vhost_hyv_srq, hdr);
	struct ib_device *ibdev = srq->ibsrq->device;
	void *data = srq->ibsrq->srq_context;

	dprint(DBG_IBV, "\n");

	srq->ibsrq->srq_context = NULL;
	kfree(data);

	ibdev->destroy_srq(srq->ibsrq);

	object_put(&srq->pd->hdr, &vhost_hyv_pd_release);
	kfree(srq);
}

DEF_HYPERCALL(hyv_ibv_create_srqX, hyv_create_srq_result, CREATE_SRQ_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_pd *pd;
	struct vhost_hyv_srq *srq;
	struct ib_udata ibudata;
	struct ib_device *ibdev;
	struct ib_srq_init_attr ibattr;
	struct ib_srq *ibsrq;
	struct vhost_hyv_srq_context *vsrq_ctx;
	hyv_create_srq_result res;
	int ret;

	dprint(DBG_IBV, "\n");

	pd = object_map_id_get_entry(&vg->pds, struct vhost_hyv_pd, hdr,
				     pd_handle);
	if (!pd) {
		ret = -EINVAL;
		goto fail;
	}

	BUG_ON(srq_type != IB_SRQT_BASIC);

	srq = kmalloc(sizeof(*srq), GFP_KERNEL);
	if (!srq) {
		ret = -ENOMEM;
		goto fail_pd;
	}
	srq->pd = pd;

	ret = udata_gv2hv_before(pd->uctx, udata, &udata_translate,
				 udata_translate_size);
	if (ret) {
		dprint(DBG_ON, "could not translate udata\n");
		goto fail_srq;
	}

	udata_to_ibudata(udata, &ibudata);

	vsrq_ctx = kmalloc(sizeof(*vsrq_ctx), GFP_KERNEL);
	if (!vsrq_ctx) {
		dprint(DBG_ON, "could not allocate qp context!\n");
		ret = -ENOMEM;
		goto fail_udata;
	}
	vsrq_ctx->vg = vg;
	vsrq_ctx->guest_handle = guest_handle;

	ibattr.srq_context = vsrq_ctx;
	ibattr.event_handler = &vhost_hyv_srq_event_handler;
	ibattr.attr.max_sge = attr.max_sge;
	ibattr.attr.max_wr = attr.max_wr;
	ibattr.attr.srq_limit = attr.srq_limit;

	ibdev = pd->ibpd->device;
	ibsrq = ibdev->create_srq(pd->ibpd, &ibattr, &ibudata);
	if (IS_ERR(ibsrq)) {
		ret = PTR_ERR(ibsrq);
		dprint(DBG_ON, "create_srq failed (%d)\n", ret);
		goto fail_context;
	}
	srq->ibsrq = ibsrq;
	srq->ibuobj.context = pd->uctx->ibuctx;
	ibsrq->uobject = &srq->ibuobj;
	ibsrq->device = ibdev;
	ibsrq->pd = pd->ibpd;
	ibsrq->srq_context = vsrq_ctx;
	ibsrq->event_handler = &vhost_hyv_srq_event_handler;
	ibsrq->srq_type = srq_type;

	udata_gv2hv_after(pd->uctx, udata, udata_translate,
			  udata_translate_size);

	ret = object_map_add(&vg->srqs, &pd->srqs, &srq->hdr);
	if (ret < 0) {
		goto fail_create;
	}

	res.srq_handle = ret;
	res.max_sge = ibattr.attr.max_sge;
	res.max_wr = ibattr.attr.max_wr;

	return res;
fail_create:
	ibdev->destroy_srq(ibsrq);
fail_context:
	kfree(vsrq_ctx);
fail_udata:
	udata_gv2hv_after(pd->uctx, udata, udata_translate,
			  udata_translate_size);
fail_srq:
	kfree(srq);
fail_pd:
	object_put(&pd->hdr, &vhost_hyv_pd_release);
fail:
	res.srq_handle = ret;
	return res;
}

DEF_HYPERCALL(hyv_ibv_modify_srqX, __s32, MODIFY_SRQ_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_srq *srq;
	struct ib_srq_attr ibattr;
	struct ib_udata ibudata;
	int ret;

	dprint(DBG_IBV, "\n");

	srq = object_map_id_get_entry(&vg->srqs, struct vhost_hyv_srq, hdr,
				      srq_handle);
	if (!srq) {
		ret = -EINVAL;
		goto fail;
	}

	ibattr.max_sge = attr.max_sge;
	ibattr.max_wr = attr.max_wr;
	ibattr.srq_limit = attr.srq_limit;

	udata_to_ibudata(udata, &ibudata);

	ret = srq->ibsrq->device->modify_srq(srq->ibsrq, &ibattr, attr_mask,
					     &ibudata);

	object_put(&srq->hdr, &vhost_hyv_srq_release);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_ibv_destroy_srqX, __s32, DESTROY_SRQ_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);

	dprint(DBG_IBV, "\n");

	return object_map_id_del(&vg->srqs, srq_handle, &vhost_hyv_srq_release);
}

void vhost_hyv_mr_release(struct object *obj)
{
	struct vhost_hyv_mr *mr = container_of(obj, struct vhost_hyv_mr, hdr);
	struct ib_device *ibdev = mr->ibmr->device;

	dprint(DBG_IBV, "\n");

	ibdev->dereg_mr(mr->ibmr);

	object_put(&mr->pd->hdr, &vhost_hyv_pd_release);
	kfree(mr);
}

DEF_HYPERCALL(hyv_ibv_reg_user_mrX, hyv_reg_user_mr_result, REG_USER_MR_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_pd *pd;
	struct vhost_hyv_mr *mr;
	struct ib_mr *ibmr;
	int ret;
	struct vhost_hyv_umem **umem;
	struct ib_udata ibudata;
	hyv_user_mem_chunk *gchunks;
	unsigned long n_chunks;
	hyv_reg_user_mr_result res;
	struct ib_device *ibdev;
	bool write;

	dprint(DBG_IBV, "\n");

	write = !!(access & ~IB_ACCESS_REMOTE_READ);

	pd = object_map_id_get_entry(&vg->pds, struct vhost_hyv_pd, hdr,
				     pd_handle);
	if (!pd) {
		ret = -EINVAL;
		goto fail;
	}
	ibdev = pd->ibpd->device;

	mr = kmalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		dprint(DBG_ON, "could not allocate mr\n");
		ret = -ENOMEM;
		goto fail_pd;
	}

	if (chunk_size % sizeof(*gchunks)) {
		dprint(DBG_ON, "invalid chunk size\n");
		ret = -EINVAL;
		goto fail_mr;
	}
	n_chunks = chunk_size / sizeof(*gchunks);

	dprint(DBG_IBV, "n_chunks: %lu\n", n_chunks);

	gchunks = kmalloc(chunk_size, GFP_KERNEL);
	if (!gchunks) {
		dprint(DBG_ON, "could not allocate chunks\n");
		ret = -ENOMEM;
		goto fail_mr;
	}

	if (copy_from_user(gchunks, mem_chunk, chunk_size)) {
		dprint(DBG_ON, "could not copy mem chunks from user!\n");
		ret = -EFAULT;
		goto fail_gchunks;
	}

	umem = vhost_hyv_ib_umem_prepare(pd->uctx, user_va, gchunks, n_chunks);
	if (IS_ERR(umem)) {
		dprint(DBG_ON, "could not prepare umem\n");
		ret = PTR_ERR(umem);
		goto fail_gchunks;
	}

	ret = udata_gv2hv_before(pd->uctx, udata, &udata_translate,
				 udata_translate_size);
	if (ret) {
		dprint(DBG_ON, "could not translate udata\n");
		goto fail_umem_prepare;
	}

	udata_to_ibudata(udata, &ibudata);

	ibmr = ibdev->reg_user_mr(pd->ibpd, user_va, size, user_va, access,
				  &ibudata);
	if (IS_ERR(ibmr)) {
		dprint(DBG_ON, "reg user mr failed\n");
		ret = PTR_ERR(ibmr);
		goto fail_udata;
	}

	udata_gv2hv_after(pd->uctx, udata, udata_translate,
			  udata_translate_size);

	mr->pd = pd;
	mr->ibmr = ibmr;
	ibmr->device = ibdev;
	ibmr->pd = pd->ibpd;
	mr->ibuobj.context = pd->uctx->ibuctx;
	ibmr->uobject = &mr->ibuobj;

	ret = vhost_hyv_ib_umem_finish(umem);
	if (ret) {
		dprint(DBG_ON, "ib umem finish error (%d)\n", ret);
		goto fail_reg_mr;
	}

	ret = object_map_add(&vg->mrs, &pd->mrs, &mr->hdr);
	if (ret < 0) {
		dprint(DBG_ON, "could not add hyv obj\n");
		goto fail_reg_mr;
	}

	res.mr_handle = ret;
	res.lkey = ibmr->lkey;
	res.rkey = ibmr->rkey;

	kfree(gchunks);

	return res;
fail_reg_mr:
	ibdev->dereg_mr(ibmr);
fail_udata:
	udata_gv2hv_after(pd->uctx, udata, udata_translate,
			  udata_translate_size);
fail_umem_prepare:
	vhost_hyv_ib_umem_finish(umem);
fail_gchunks:
	kfree(gchunks);
fail_mr:
	kfree(mr);
fail_pd:
	object_put(&pd->hdr, &vhost_hyv_pd_release);
fail:
	return (hyv_reg_user_mr_result) { .mr_handle = ret };
}

DEF_HYPERCALL(hyv_ibv_dereg_mrX, __s32, DEREG_MR_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);

	dprint(DBG_IBV, "\n");

	return object_map_id_del(&vg->mrs, mr_handle, &vhost_hyv_mr_release);
}

DEF_HYPERCALL(hyv_ibv_post_send_nullX, __s32, POST_SEND_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_qp *qp;
	int ret = 0;

	dprint(DBG_IBV, "\n");

	qp = object_map_id_get_entry(&vg->qps, struct vhost_hyv_qp, hdr,
				     qp_handle);
	if (!qp) {
		ret = -EINVAL;
		goto fail;
	}

	ret = qp->ibqp->device->post_send(qp->ibqp, NULL, NULL);

	object_put(&qp->hdr, &vhost_hyv_qp_release);
fail:
	return ret;
}
