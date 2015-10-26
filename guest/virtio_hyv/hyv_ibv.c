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

#include <linux/module.h>
#include <linux/list.h>
#ifdef CONFIG_X86
#include <asm/cacheflush.h>
#endif
#include <rdma/ib_user_verbs.h>

#include <hypercall_guest.h>
#include <hyv_hypercall.h>

#include "virtio_hyv.h"
#include "virtio_hyv_debug.h"

#include "hyv_mem.h"

#include <hyv.h>

static hyv_udata *udata_create(struct ib_udata *ibudata)
{
	int ret;
	hyv_udata *udata;
	unsigned long inlen;

	BUG_ON(ibudata->inlen < sizeof(struct ib_uverbs_cmd_hdr));

	inlen = ibudata->inlen - sizeof(struct ib_uverbs_cmd_hdr);

	udata = kmalloc(sizeof(*udata) + inlen + ibudata->outlen, GFP_KERNEL);
	if (!udata) {
		dprint(DBG_ON, "could not allocate udata\n");
		ret = -ENOMEM;
		goto fail;
	}
	udata->in = inlen;
	udata->out = ibudata->outlen;

	ret = ib_copy_from_udata(udata->data, ibudata, inlen);
	if (ret) {
		dprint(DBG_ON, "copy from udata failed\n");
		goto fail_udata;
	}

	return udata;
fail_udata:
	kfree(udata);
fail:
	return ERR_PTR(ret);
}

static void udata_destroy(hyv_udata *udata)
{
	kfree(udata);
}

static int udata_copy_out(hyv_udata *udata, struct ib_udata *ibudata)
{
	int ret = 0;
	void *out = udata->data + udata->in;

	ret = ib_copy_to_udata(ibudata, out, udata->out);
	if (ret) {
		dprint(DBG_ON, "copy to udata failed\n");
		return ret;
	}
	return 0;
}

#define UDATA_ARG(udata) udata, (sizeof(*udata) + udata->in + udata->out)

hyv_udata_translate *udata_translate_create(hyv_udata *udata,
					    struct hyv_user_mem **umem,
					    struct hyv_udata_gvm *udata_gvm,
					    uint32_t udata_gvm_num,
					    uint32_t *n_chunks_total)
{
	struct
	{
		hyv_user_mem_chunk *data;
		unsigned long n;
	} *chunks;
	uint32_t chunks_total = 0;
	hyv_udata_translate *udata_trans_iter;
	hyv_udata_translate *udata_translate;
	uint32_t i, j;
	int ret;

	chunks = kmalloc(sizeof(*chunks) * udata_gvm_num, GFP_KERNEL);
	if (!chunks) {
		dprint(DBG_ON, "could not allocate chunks\n");
		ret = -ENOMEM;
		goto fail;
	}

	for (i = 0; i < udata_gvm_num; i++) {
		__u64 *va = (__u64 *)&udata->data[udata_gvm[i].udata_offset];
		dprint(DBG_IBV, "masked va: 0x%llx\n", *va & udata_gvm[i].mask);
		umem[i] =
		    hyv_pin_user_mem(*va & udata_gvm[i].mask, udata_gvm[i].size,
				     &chunks[i].data, &chunks[i].n, true);
		if (IS_ERR(umem[i])) {
			dprint(DBG_ON, "could not pin user memory\n");
			ret = PTR_ERR(umem[i]);
			goto fail_pin;
		}

		chunks_total += chunks[i].n;
	}
	*n_chunks_total = chunks_total;

	if (udata_gvm_num) {
		udata_translate =
		    kmalloc(sizeof(*udata_translate) * udata_gvm_num +
				sizeof(hyv_user_mem_chunk) * chunks_total,
			    GFP_KERNEL);
	} else {
		udata_translate = kzalloc(sizeof(*udata_translate), GFP_KERNEL);
	}
	if (!udata_translate) {
		dprint(DBG_ON, "could not alloc udata translate\n");
		ret = -ENOMEM;
		goto fail_pin;
	}

	udata_trans_iter = udata_translate;
	for (j = 0; j < udata_gvm_num; j++) {
		uint32_t n_chunks = chunks[j].n;
		udata_trans_iter->udata_offset = udata_gvm[j].udata_offset;
		udata_trans_iter->n_chunks = n_chunks;
		udata_trans_iter->type = udata_gvm[j].type;
		memcpy(udata_trans_iter->chunk, chunks[j].data,
		       sizeof(hyv_user_mem_chunk) * n_chunks);
		udata_trans_iter =
		    (hyv_udata_translate *)&udata_trans_iter->chunk[n_chunks];
	}

	kfree(chunks);

	return udata_translate;
fail_pin:
	for (j = 0; j < i; j++) {
		hyv_unpin_user_mem(umem[j]);
	}
	kfree(chunks);
fail:
	return ERR_PTR(ret);
}

void udata_translate_destroy(hyv_udata_translate *udata_translate)
{
	kfree(udata_translate);
}

#define UDATA_TRANSLATE_ARG(udata_translate, udata_gvm_num, n_chunks_total)    \
	udata_translate,                                                       \
	    sizeof(*udata_translate) * (udata_gvm_num ? udata_gvm_num : 1) +   \
		sizeof(hyv_user_mem_chunk) * n_chunks_total

int hyv_ibv_query_device(struct ib_device *ibdev, struct ib_device_attr *ibattr)
{
	struct hyv_device *dev = ibdev_to_hyv(ibdev);
	hyv_query_device_result *attr;
	int ret, hret;

	dprint(DBG_IBV, "\n");

	attr = kmalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) {
		dprint(DBG_ON, "could not allocate device attr\n");
		return -ENOMEM;
	}

	ret = hyv_ibv_query_deviceX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, dev->host_handle, attr, sizeof(*attr));
	if (ret || hret) {
		dprint(DBG_ON, "could not query device on host\n");
		kfree(attr);
		return ret ? ret : hret;
	}

	ibattr->fw_ver = attr->fw_ver;
	ibattr->sys_image_guid = attr->sys_image_guid;
	ibattr->max_mr_size = attr->max_mr_size;
	ibattr->page_size_cap = attr->page_size_cap;
	ibattr->vendor_id = attr->vendor_id;
	ibattr->vendor_part_id = attr->vendor_part_id;
	ibattr->hw_ver = attr->hw_ver;
	ibattr->max_qp = attr->max_qp;
	ibattr->max_qp_wr = attr->max_qp_wr;
	ibattr->device_cap_flags = attr->device_cap_flags;
	ibattr->max_sge = attr->max_sge;
	ibattr->max_sge_rd = attr->max_sge_rd;
	ibattr->max_cq = attr->max_cq;
	ibattr->max_cqe = attr->max_cqe;
	ibattr->max_mr = attr->max_mr;
	ibattr->max_pd = attr->max_pd;
	ibattr->max_qp_rd_atom = attr->max_qp_rd_atom;
	ibattr->max_ee_rd_atom = attr->max_ee_rd_atom;
	ibattr->max_res_rd_atom = attr->max_res_rd_atom;
	ibattr->max_qp_init_rd_atom = attr->max_qp_init_rd_atom;
	ibattr->max_ee_init_rd_atom = attr->max_ee_init_rd_atom;
	ibattr->atomic_cap = attr->atomic_cap;
	ibattr->max_ee = attr->max_ee;
	ibattr->max_rdd = attr->max_rdd;
	ibattr->max_mw = attr->max_mw;
	ibattr->max_raw_ipv6_qp = attr->max_raw_ipv6_qp;
	ibattr->max_raw_ethy_qp = attr->max_raw_ethy_qp;
	ibattr->max_mcast_grp = attr->max_mcast_grp;
	ibattr->max_mcast_qp_attach = attr->max_mcast_qp_attach;
	ibattr->max_total_mcast_qp_attach = attr->max_total_mcast_qp_attach;
	ibattr->max_ah = attr->max_ah;
	ibattr->max_fmr = attr->max_fmr;
	ibattr->max_map_per_fmr = attr->max_map_per_fmr;
	ibattr->max_srq = attr->max_srq;
	ibattr->max_srq_wr = attr->max_srq_wr;
	ibattr->max_srq_sge = attr->max_srq_sge;
	ibattr->max_pkeys = attr->max_pkeys;
	ibattr->local_ca_ack_delay = attr->local_ca_ack_delay;

	kfree(attr);

	return 0;
}
EXPORT_SYMBOL(hyv_ibv_query_device);

int hyv_ibv_query_port(struct ib_device *ibdev, u8 port,
		       struct ib_port_attr *ibattr)
{
	struct hyv_device *dev = ibdev_to_hyv(ibdev);
	hyv_query_port_result *attr;
	int ret, hret;

	dprint(DBG_IBV, "\n");

	attr = kmalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) {
		dprint(DBG_ON, "could not allocate device attr\n");
		return -ENOMEM;
	}

	ret = hyv_ibv_query_portX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, dev->host_handle, port, attr, sizeof(*attr));
	if (ret || hret) {
		dprint(DBG_ON, "could not query port on host\n");
		kfree(attr);
		return ret ? ret : hret;
	}

	ibattr->state = attr->state;
	ibattr->max_mtu = attr->max_mtu;
	ibattr->active_mtu = attr->active_mtu;
	ibattr->gid_tbl_len = attr->gid_tbl_len;
	ibattr->port_cap_flags = attr->port_cap_flags;
	ibattr->max_msg_sz = attr->max_msg_sz;
	ibattr->bad_pkey_cntr = attr->bad_pkey_cntr;
	ibattr->qkey_viol_cntr = attr->qkey_viol_cntr;
	ibattr->pkey_tbl_len = attr->pkey_tbl_len;
	ibattr->lid = attr->lid;
	ibattr->sm_lid = attr->sm_lid;
	ibattr->lmc = attr->lmc;
	ibattr->max_vl_num = attr->max_vl_num;
	ibattr->sm_sl = attr->sm_sl;
	ibattr->subnet_timeout = attr->subnet_timeout;
	ibattr->init_type_reply = attr->init_type_reply;
	ibattr->active_width = attr->active_width;
	ibattr->active_speed = attr->active_speed;
	ibattr->phys_state = attr->phys_state;

	kfree(attr);

	return 0;
}
EXPORT_SYMBOL(hyv_ibv_query_port);

int hyv_ibv_query_pkey(struct ib_device *ibdev, u8 port, u16 index, u16 *pkey)
{
	struct hyv_device *dev = ibdev_to_hyv(ibdev);
	int ret, hret;

	dprint(DBG_IBV, "\n");

	ret = hyv_ibv_query_pkeyX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, dev->host_handle, port, index);
	if (ret || hret < 0) {
		dprint(DBG_ON, "could not query pkey on host\n");
		return ret ? ret : hret;
	}

	*pkey = hret;

	return 0;
}
EXPORT_SYMBOL(hyv_ibv_query_pkey);

int hyv_ibv_query_gid(struct ib_device *ibdev, u8 port, int index,
		      union ib_gid *ibgid)
{
	struct hyv_device *dev = ibdev_to_hyv(ibdev);
	hyv_query_gid_result *gid;
	int ret, hret;

	dprint(DBG_IBV, "\n");

	gid = kmalloc(sizeof(*gid), GFP_KERNEL);
	if (!gid) {
		dprint(DBG_ON, "could not allocate device attr\n");
		return -ENOMEM;
	}

	ret = hyv_ibv_query_gidX(&dev->vg->vq_hcall,
				 HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
				 GFP_KERNEL, &hret, dev->host_handle, port,
				 index, gid, sizeof(*gid));
	if (ret || hret) {
		dprint(DBG_ON, "could not query gid on host\n");
		kfree(gid);
		return ret ? ret : hret;
	}

	memcpy(ibgid, gid, sizeof(*ibgid));

	kfree(gid);
	return 0;
}
EXPORT_SYMBOL(hyv_ibv_query_gid);

struct ib_ucontext *hyv_ibv_alloc_ucontext(struct ib_device *ibdev,
					   struct ib_udata *ibudata)
{
	struct hyv_device *dev = ibdev_to_hyv(ibdev);
	struct hyv_ucontext *uctx;
	int ret, hret;
	hyv_udata *udata;

	dprint(DBG_IBV, "\n");

	uctx = kmalloc(sizeof(*uctx), GFP_KERNEL);
	if (!uctx) {
		dprint(DBG_ON, "could not allocate user context\n");
		ret = -ENOMEM;
		goto fail;
	}
	INIT_LIST_HEAD(&uctx->mmap_list);
	spin_lock_init(&uctx->mmap_lock);

	udata = udata_create(ibudata);
	if (IS_ERR(udata)) {
		ret = PTR_ERR(udata);
		goto fail_uctx;
	}

	ret = hyv_ibv_alloc_ucontextX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, dev->host_handle, UDATA_ARG(udata));
	if (ret || hret < 0) {
		dprint(DBG_ON, "could not query gid on host\n");
		ret = ret ? ret : hret;
		goto fail_udata;
	}
	uctx->host_handle = hret;

	ret = udata_copy_out(udata, ibudata);
	udata_destroy(udata);
	if (ret) {
		goto fail_alloc_ucontext;
	}

	/* XXX */
	uctx->ibuctx.device = ibdev;

	return &uctx->ibuctx;

fail_udata:
	udata_destroy(udata);
fail_uctx:
	kfree(uctx);
fail:
	return ERR_PTR(ret);

fail_alloc_ucontext:
	/* in non-error case ib core would take care of this */
	uctx->ibuctx.device = ibdev;
	hyv_ibv_dealloc_ucontext(&uctx->ibuctx);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(hyv_ibv_alloc_ucontext);

int hyv_ibv_dealloc_ucontext(struct ib_ucontext *ibuctx)
{
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);
	struct hyv_device *dev = ibdev_to_hyv(ibuctx->device);
	int ret, hret;

	dprint(DBG_IBV, "\n");

	ret = hyv_ibv_dealloc_ucontextX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, uctx->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not dealloc ucontext on host\n");
		return ret ? ret : hret;
	}

	kfree(uctx);
	return 0;
}
EXPORT_SYMBOL(hyv_ibv_dealloc_ucontext);

struct ib_pd *hyv_ibv_alloc_pd(struct ib_device *ibdev,
			       struct ib_ucontext *ibuctx,
			       struct ib_udata *ibudata)
{
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);
	struct hyv_device *dev = ibdev_to_hyv(ibdev);
	struct hyv_pd *pd;
	hyv_udata *udata;
	int ret, hret;

	dprint(DBG_IBV, "\n");

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd) {
		dprint(DBG_ON, "could not allocate pd\n");
		ret = -ENOMEM;
		goto fail;
	}

	udata = udata_create(ibudata);
	if (IS_ERR(udata)) {
		ret = PTR_ERR(udata);
		goto fail_pd;
	}

	ret = hyv_ibv_alloc_pdX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, uctx->host_handle, UDATA_ARG(udata));
	if (ret || hret < 0) {
		dprint(DBG_ON, "could not alloc pd on host\n");
		ret = ret ? ret : hret;
		goto fail_udata;
	}
	pd->host_handle = hret;

	ret = udata_copy_out(udata, ibudata);
	udata_destroy(udata);
	if (ret) {
		goto fail_alloc;
	}

	return &pd->ibpd;

fail_udata:
	udata_destroy(udata);
fail_pd:
	kfree(pd);
fail:
	return ERR_PTR(ret);

fail_alloc:
	hyv_ibv_dealloc_pd(&pd->ibpd);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(hyv_ibv_alloc_pd);

int hyv_ibv_dealloc_pd(struct ib_pd *ibpd)
{
	struct hyv_device *dev = ibdev_to_hyv(ibpd->device);
	struct hyv_pd *pd = ibpd_to_hyv(ibpd);
	int ret, hret;

	dprint(DBG_IBV, "\n");

	ret = hyv_ibv_dealloc_pdX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, pd->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not dealloc pd on host\n");
		return ret ? ret : hret;
	}

	if (pd->dma_mr_cache) {
		kfree(pd->dma_mr_cache);
	}

	kfree(pd);
	return 0;
}
EXPORT_SYMBOL(hyv_ibv_dealloc_pd);

struct ib_cq *hyv_ibv_create_cq_gv2hv(struct ib_device *ibdev, int entries,
				      int vector, struct ib_ucontext *ibuctx,
				      struct ib_udata *ibudata,
				      struct hyv_udata_gvm *udata_gvm,
				      uint32_t udata_gvm_num)
{
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);
	struct hyv_device *dev = ibdev_to_hyv(ibdev);
	struct hyv_cq *cq;
	int ret;
	hyv_create_cq_result res;
	hyv_udata_translate *udata_translate;
	hyv_udata *udata;
	uint32_t n_chunks_total;
	uint32_t i;

	dprint(DBG_IBV, "\n");

	cq = kmalloc(sizeof(*cq), GFP_KERNEL);
	if (!cq) {
		dprint(DBG_ON, "could not allocate cq\n");
		ret = -ENOMEM;
		goto fail;
	}

	udata = udata_create(ibudata);
	if (IS_ERR(udata)) {
		ret = PTR_ERR(udata);
		goto fail_cq;
	}

	cq->n_umem = udata_gvm_num;

	cq->umem = kmalloc(sizeof(*cq->umem) * udata_gvm_num, GFP_KERNEL);
	if (!cq->umem) {
		dprint(DBG_ON, "could not allocate umem\n");
		ret = -ENOMEM;
		goto fail_udata;
	}

	udata_translate = udata_translate_create(
	    udata, cq->umem, udata_gvm, udata_gvm_num, &n_chunks_total);
	if (IS_ERR(udata_translate)) {
		dprint(DBG_ON, "could not translate udata\n");
		ret = PTR_ERR(udata_translate);
		goto fail_umem;
	}

	ret = hyv_ibv_create_cqX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &res, (__u64)cq, uctx->host_handle, entries, vector,
	    UDATA_ARG(udata),
	    UDATA_TRANSLATE_ARG(udata_translate, udata_gvm_num,
				n_chunks_total));
	if (ret || res.cq_handle < 0) {
		dprint(DBG_ON, "could not create cq on host\n");
		ret = ret ? ret : res.cq_handle;
		goto fail_udata_translate;
	}
	cq->host_handle = res.cq_handle;
	cq->ibcq.cqe = res.cqe;

	udata_translate_destroy(udata_translate);

	ret = udata_copy_out(udata, ibudata);
	udata_destroy(udata);
	if (ret) {
		goto fail_create;
	}

	return &cq->ibcq;
fail_udata_translate:
	for (i = 0; i < cq->n_umem; i++) {
		hyv_unpin_user_mem(cq->umem[i]);
	}
	udata_translate_destroy(udata_translate);
fail_umem:
	kfree(cq->umem);
fail_udata:
	udata_destroy(udata);
fail_cq:
	kfree(cq);
fail:
	return ERR_PTR(ret);

fail_create:
	hyv_ibv_destroy_cq(&cq->ibcq);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(hyv_ibv_create_cq_gv2hv);

struct ib_cq *hyv_ibv_create_cq(struct ib_device *ibdev, int entries,
				int vector, struct ib_ucontext *ibuctx,
				struct ib_udata *ibudata)
{
	return hyv_ibv_create_cq_gv2hv(ibdev, entries, vector, ibuctx, ibudata,
				       NULL, 0);
}
EXPORT_SYMBOL(hyv_ibv_create_cq);

int hyv_ibv_destroy_cq(struct ib_cq *ibcq)
{
	struct hyv_device *dev = ibdev_to_hyv(ibcq->device);
	struct hyv_cq *cq = ibcq_to_hyv(ibcq);
	int ret, hret;
	uint32_t i;

	dprint(DBG_IBV, "\n");

	ret = hyv_ibv_destroy_cqX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, cq->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not destroy cq on host\n");
		return ret ? ret : hret;
	}

	for (i = 0; i < cq->n_umem; i++) {
		hyv_unpin_user_mem(cq->umem[i]);
	}
	kfree(cq->umem);

	kfree(cq);
	return 0;
}
EXPORT_SYMBOL(hyv_ibv_destroy_cq);

struct ib_qp *hyv_ibv_create_qp_gv2hv(struct ib_pd *ibpd,
				      struct ib_qp_init_attr *ibinit_attr,
				      struct ib_udata *ibudata,
				      struct hyv_udata_gvm *udata_gvm,
				      uint32_t udata_gvm_num)
{
	struct hyv_device *dev = ibdev_to_hyv(ibpd->device);
	struct hyv_pd *pd = ibpd_to_hyv(ibpd);
	struct hyv_qp *qp;
	struct hyv_cq *send_cq, *recv_cq;
	struct hyv_srq *srq = NULL;
	int ret, hret;
	hyv_create_qp_result *res;
	hyv_qp_init_attr init_attr;
	hyv_udata_translate *udata_translate;
	hyv_udata *udata;
	uint32_t n_chunks_total, i;

	dprint(DBG_IBV, "\n");

	send_cq = ibcq_to_hyv(ibinit_attr->send_cq);
	recv_cq = ibcq_to_hyv(ibinit_attr->recv_cq);

	if (ibinit_attr->srq) {
		srq = ibsrq_to_hyv(ibinit_attr->srq);
	}

	qp = kmalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		dprint(DBG_ON, "could not allocate qp\n");
		ret = -ENOMEM;
		goto fail;
	}

	res = kmalloc(sizeof(*res), GFP_KERNEL);
	if (!res) {
		dprint(DBG_ON, "could not allocate result");
		ret = -ENOMEM;
		goto fail_qp;
	}

	udata = udata_create(ibudata);
	if (IS_ERR(udata)) {
		ret = PTR_ERR(udata);
		goto fail_res;
	}

	qp->n_umem = udata_gvm_num;

	qp->umem = kmalloc(sizeof(*qp->umem) * udata_gvm_num, GFP_KERNEL);
	if (!qp->umem) {
		dprint(DBG_ON, "could not allocate umem\n");
		ret = -ENOMEM;
		goto fail_udata;
	}

	udata_translate = udata_translate_create(
	    udata, qp->umem, udata_gvm, udata_gvm_num, &n_chunks_total);
	if (IS_ERR(udata_translate)) {
		dprint(DBG_ON, "could not translate udata\n");
		ret = PTR_ERR(udata_translate);
		goto fail_umem;
	}

	init_attr.send_cq_handle = send_cq->host_handle;
	init_attr.recv_cq_handle = recv_cq->host_handle;
	init_attr.srq_handle = ibinit_attr->srq ? srq->host_handle : -1;
	init_attr.xrcd_handle = -1;
	copy_ib_qp_cap_to_hyv(&ibinit_attr->cap, &init_attr.cap);
	init_attr.sq_sig_type = ibinit_attr->sq_sig_type;
	init_attr.qp_type = ibinit_attr->qp_type;
	init_attr.create_flags = ibinit_attr->create_flags;
	init_attr.port_num = ibinit_attr->port_num;

	ret = hyv_ibv_create_qpX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, (__u64)qp, pd->host_handle, init_attr, res,
	    sizeof(*res), UDATA_ARG(udata),
	    UDATA_TRANSLATE_ARG(udata_translate, udata_gvm_num,
				n_chunks_total));
	if (ret || hret) {
		dprint(DBG_ON, "could not create qp on host\n");
		ret = ret ? ret : hret;
		goto fail_udata_translate;
	}
	qp->host_handle = res->qp_handle;
	qp->ibqp.qp_num = res->qpn;
	copy_hyv_qp_cap_to_ib(&res->cap, &ibinit_attr->cap);

	udata_translate_destroy(udata_translate);

	ret = udata_copy_out(udata, ibudata);
	udata_destroy(udata);
	if (ret) {
		goto fail_alloc;
	}

	kfree(res);

	return &qp->ibqp;
fail_udata_translate:
	for (i = 0; i < qp->n_umem; i++) {
		hyv_unpin_user_mem(qp->umem[i]);
	}
	udata_translate_destroy(udata_translate);
fail_umem:
	kfree(qp->umem);
fail_udata:
	udata_destroy(udata);
fail_res:
	kfree(res);
fail_qp:
	kfree(qp);
fail:
	return ERR_PTR(ret);

fail_alloc:
	kfree(res);
	hyv_ibv_destroy_qp(&qp->ibqp);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(hyv_ibv_create_qp_gv2hv);

struct ib_qp *hyv_ibv_create_qp(struct ib_pd *ibpd,
				struct ib_qp_init_attr *attr,
				struct ib_udata *ibudata)
{
	return hyv_ibv_create_qp_gv2hv(ibpd, attr, ibudata, NULL, 0);
}
EXPORT_SYMBOL(hyv_ibv_create_qp);

int hyv_ibv_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *ibattr,
		      int attr_mask, struct ib_udata *ibudata)
{
	struct hyv_device *dev = ibdev_to_hyv(ibqp->device);
	struct hyv_qp *qp = ibqp_to_hyv(ibqp);
	hyv_qp_attr attr;
	int ret = 0, hret;
	hyv_udata *udata;

	dprint(DBG_IBV, "attr_mask: %x\n", attr_mask);

	copy_ib_qp_attr_to_hyv(ibattr, &attr);

	udata = udata_create(ibudata);
	if (IS_ERR(udata)) {
		ret = PTR_ERR(udata);
		goto fail;
	}

	ret = hyv_ibv_modify_qpX(&dev->vg->vq_hcall,
				 HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
				 GFP_KERNEL, &hret, qp->host_handle, attr,
				 attr_mask, UDATA_ARG(udata));
	if (ret || hret) {
		dprint(DBG_ON, "could not modify qp on host\n");
		ret = ret ? ret : hret;
		goto fail_udata;
	}

	ret = udata_copy_out(udata, ibudata);

fail_udata:
	udata_destroy(udata);
fail:
	return ret;
}
EXPORT_SYMBOL(hyv_ibv_modify_qp);

int hyv_ibv_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *ibattr,
		     int attr_mask, struct ib_qp_init_attr *ibinit_attr)
{
	struct hyv_device *dev = ibdev_to_hyv(ibqp->device);
	struct hyv_qp *qp = ibqp_to_hyv(ibqp);
	hyv_qp_attr *attr;
	hyv_qp_init_attr *init_attr;
	int ret = 0, hret;

	dprint(DBG_IBV, "\n");

	attr = kmalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) {
		dprint(DBG_ON, "could not alloc attr\n");
		ret = -ENOMEM;
		goto fail;
	}

	init_attr = kmalloc(sizeof(*init_attr), GFP_KERNEL);
	if (!init_attr) {
		dprint(DBG_ON, "could not alloc init attr\n");
		ret = -ENOMEM;
		goto fail_attr;
	}

	ret = hyv_ibv_query_qpX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, qp->host_handle, attr_mask, attr, sizeof(*attr),
	    init_attr, sizeof(*init_attr));
	if (ret || hret) {
		dprint(DBG_ON, "could not query qp on host\n");
		ret = ret ? ret : hret;
		goto fail_init_attr;
	}

	copy_hyv_qp_attr_to_ib(attr, ibattr);
	copy_hyv_qp_cap_to_ib(&init_attr->cap, &ibinit_attr->cap);
	ibinit_attr->create_flags = init_attr->create_flags;
	ibinit_attr->sq_sig_type = init_attr->sq_sig_type;

fail_init_attr:
	kfree(init_attr);
fail_attr:
	kfree(attr);
fail:
	return ret;
}
EXPORT_SYMBOL(hyv_ibv_query_qp);

int hyv_ibv_destroy_qp(struct ib_qp *ibqp)
{
	struct hyv_device *dev = ibdev_to_hyv(ibqp->device);
	struct hyv_qp *qp = ibqp_to_hyv(ibqp);
	int ret, hret;
	uint32_t i;

	dprint(DBG_IBV, "\n");

	ret = hyv_ibv_destroy_qpX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, qp->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not destroy qp on host\n");
		return ret ? ret : hret;
	}

	for (i = 0; i < qp->n_umem; i++) {
		hyv_unpin_user_mem(qp->umem[i]);
	}
	kfree(qp->umem);

	kfree(qp);
	return 0;
}
EXPORT_SYMBOL(hyv_ibv_destroy_qp);

struct ib_srq *hyv_ibv_create_srq_gv2hv(struct ib_pd *ibpd,
					struct ib_srq_init_attr *ibattr,
					struct ib_udata *ibudata,
					struct hyv_udata_gvm *udata_gvm,
					uint32_t udata_gvm_num)
{
	struct hyv_device *dev = ibdev_to_hyv(ibpd->device);
	struct hyv_pd *pd = ibpd_to_hyv(ibpd);
	struct hyv_srq *srq;
	int ret;
	hyv_create_srq_result res;
	hyv_srq_attr attr;
	hyv_udata_translate *udata_translate;
	hyv_udata *udata;
	uint32_t n_chunks_total, i;

	dprint(DBG_IBV, "\n");

	srq = kmalloc(sizeof(*srq), GFP_KERNEL);
	if (!srq) {
		dprint(DBG_ON, "could not allocate srq\n");
		ret = -ENOMEM;
		goto fail;
	}

	udata = udata_create(ibudata);
	if (IS_ERR(udata)) {
		ret = PTR_ERR(udata);
		goto fail_srq;
	}

	srq->n_umem = udata_gvm_num;

	srq->umem = kmalloc(sizeof(*srq->umem) * udata_gvm_num, GFP_KERNEL);
	if (!srq->umem) {
		dprint(DBG_ON, "could not allocate umem\n");
		ret = -ENOMEM;
		goto fail_udata;
	}

	udata_translate = udata_translate_create(
	    udata, srq->umem, udata_gvm, udata_gvm_num, &n_chunks_total);
	if (IS_ERR(udata_translate)) {
		dprint(DBG_ON, "could not translate udata\n");
		ret = PTR_ERR(udata_translate);
		goto fail_umem;
	}

	attr.max_sge = ibattr->attr.max_sge;
	attr.max_wr = ibattr->attr.max_wr;
	attr.srq_limit = ibattr->attr.srq_limit;

	ret = hyv_ibv_create_srqX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &res, (__u64)srq, pd->host_handle, attr,
	    ibattr->srq_type, -1, -1, UDATA_ARG(udata),
	    UDATA_TRANSLATE_ARG(udata_translate, udata_gvm_num,
				n_chunks_total));
	if (ret || res.srq_handle < 0) {
		dprint(DBG_ON, "could not create qp on host\n");
		ret = ret ? ret : res.srq_handle;
		goto fail_udata_translate;
	}
	srq->host_handle = res.srq_handle;
	ibattr->attr.max_sge = res.max_sge;
	ibattr->attr.max_wr = res.max_wr;

	udata_translate_destroy(udata_translate);

	ret = udata_copy_out(udata, ibudata);
	udata_destroy(udata);
	if (ret) {
		goto fail_alloc;
	}

	return &srq->ibsrq;
fail_udata_translate:
	for (i = 0; i < srq->n_umem; i++) {
		hyv_unpin_user_mem(srq->umem[i]);
	}
	udata_translate_destroy(udata_translate);
fail_umem:
	kfree(srq->umem);
fail_udata:
	udata_destroy(udata);
fail_srq:
	kfree(srq);
fail:
	return ERR_PTR(ret);

fail_alloc:
	hyv_ibv_destroy_srq(&srq->ibsrq);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(hyv_ibv_create_srq_gv2hv);

struct ib_srq *hyv_ibv_create_srq(struct ib_pd *ibpd,
				  struct ib_srq_init_attr *attr,
				  struct ib_udata *ibudata)
{
	return hyv_ibv_create_srq_gv2hv(ibpd, attr, ibudata, NULL, 0);
}
EXPORT_SYMBOL(hyv_ibv_create_srq);

int hyv_ibv_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *ibattr,
		       enum ib_srq_attr_mask attr_mask,
		       struct ib_udata *ibudata)
{
	struct hyv_device *dev = ibdev_to_hyv(ibsrq->device);
	struct hyv_srq *srq = ibsrq_to_hyv(ibsrq);
	hyv_srq_attr attr;
	int ret = 0, hret;
	hyv_udata *udata;

	dprint(DBG_IBV, "attr_mask: %x\n", attr_mask);

	attr.max_sge = ibattr->max_sge;
	attr.max_wr = ibattr->max_wr;
	attr.srq_limit = ibattr->srq_limit;

	udata = udata_create(ibudata);
	if (IS_ERR(udata)) {
		ret = PTR_ERR(udata);
		goto fail;
	}

	ret = hyv_ibv_modify_srqX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, srq->host_handle, attr, attr_mask,
	    UDATA_ARG(udata));
	if (ret || hret) {
		dprint(DBG_ON, "could not modify qp on host\n");
		ret = ret ? ret : hret;
		goto fail_udata;
	}

	ret = udata_copy_out(udata, ibudata);

fail_udata:
	udata_destroy(udata);
fail:
	return ret;
}
EXPORT_SYMBOL(hyv_ibv_modify_srq);

int hyv_ibv_destroy_srq(struct ib_srq *ibsrq)
{
	struct hyv_device *dev = ibdev_to_hyv(ibsrq->device);
	struct hyv_srq *srq = ibsrq_to_hyv(ibsrq);
	int ret, hret;
	uint32_t i;

	dprint(DBG_IBV, "\n");

	ret = hyv_ibv_destroy_srqX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, srq->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not destroy qp on host\n");
		return ret ? ret : hret;
	}

	for (i = 0; i < srq->n_umem; i++) {
		hyv_unpin_user_mem(srq->umem[i]);
	}
	kfree(srq->umem);

	kfree(srq);
	return 0;
}
EXPORT_SYMBOL(hyv_ibv_destroy_srq);

struct ib_mr *hyv_ibv_reg_user_mr_gv2hv(struct ib_pd *ibpd, u64 user_va,
					u64 size, u64 io_va, int access,
					struct ib_udata *ibudata,
					struct hyv_udata_gvm *udata_gvm,
					uint32_t udata_gvm_num)
{
	struct hyv_device *dev = ibdev_to_hyv(ibpd->device);
	struct hyv_pd *pd = ibpd_to_hyv(ibpd);
	struct hyv_mr *mr;
	hyv_reg_user_mr_result res;
	hyv_user_mem_chunk *umem_chunks;
	hyv_udata_translate *udata_translate;
	struct hyv_user_mem *umem;
	uint32_t n_chunks_total, i;
	unsigned long n_chunks;
	hyv_udata *udata;
	bool write;
	int ret;

	dprint(DBG_IBV, "\n");

	/* we do not support this yet
	 * actually never saw a usage of this feature! */
	BUG_ON(user_va != io_va);

	write = !!(access & ~IB_ACCESS_REMOTE_READ);

	mr = kmalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		dprint(DBG_ON, "could not allocate mr\n");
		ret = -ENOMEM;
		goto fail;
	}

	umem = hyv_pin_user_mem(user_va, size, &umem_chunks, &n_chunks, write);
	if (IS_ERR(umem)) {
		dprint(DBG_ON, "could not pin user memory\n");
		ret = PTR_ERR(umem);
		goto fail_mr;
	}

	udata = udata_create(ibudata);
	if (IS_ERR(udata)) {
		dprint(DBG_ON, "pre udata failed!\n");
		ret = PTR_ERR(udata);
		goto fail_pin;
	}

	mr->n_umem = udata_gvm_num;

	mr->umem = kmalloc(sizeof(*mr->umem) * (udata_gvm_num + 1), GFP_KERNEL);
	if (!mr->umem) {
		dprint(DBG_ON, "could not allocate umem\n");
		ret = -ENOMEM;
		goto fail_udata;
	}
	mr->umem[0] = umem;

	udata_translate = udata_translate_create(
	    udata, mr->umem + 1, udata_gvm, udata_gvm_num, &n_chunks_total);
	if (IS_ERR(udata_translate)) {
		dprint(DBG_ON, "could not translate udata\n");
		ret = PTR_ERR(udata_translate);
		goto fail_umem;
	}

	ret = hyv_ibv_reg_user_mrX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &res, pd->host_handle, user_va, size, access,
	    umem_chunks, n_chunks * sizeof(*umem_chunks), UDATA_ARG(udata),
	    UDATA_TRANSLATE_ARG(udata_translate, udata_gvm_num,
				n_chunks_total));
	if (ret || res.mr_handle < 0) {
		dprint(DBG_ON, "could not reg user mr on host\n");
		ret = ret ? ret : res.mr_handle;
		goto fail_udata_translate;
	}
	mr->access = access;
	mr->host_handle = res.mr_handle;
	mr->ibmr.lkey = res.lkey;
	mr->ibmr.rkey = res.rkey;

	udata_translate_destroy(udata_translate);

	kfree(umem_chunks);

	ret = udata_copy_out(udata, ibudata);
	udata_destroy(udata);
	if (ret) {
		dprint(DBG_ON, "could not copy response\n");
		hyv_ibv_dereg_mr(&mr->ibmr);
		ret = -EFAULT;
		goto fail;
	}

	return &mr->ibmr;
fail_udata_translate:
	for (i = 0; i < mr->n_umem; i++) {
		hyv_unpin_user_mem(mr->umem[i]);
	}
	udata_translate_destroy(udata_translate);
fail_umem:
	kfree(mr->umem);
fail_udata:
	udata_destroy(udata);
fail_pin:
	kfree(umem_chunks);
	hyv_unpin_user_mem(umem);
fail_mr:
	kfree(mr);
fail:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(hyv_ibv_reg_user_mr_gv2hv);

struct ib_mr *hyv_ibv_reg_user_mr(struct ib_pd *ibpd, u64 user_va, u64 size,
				  u64 io_va, int access,
				  struct ib_udata *ibudata)
{
	return hyv_ibv_reg_user_mr_gv2hv(ibpd, user_va, size, io_va, access,
					 ibudata, NULL, 0);
}
EXPORT_SYMBOL(hyv_ibv_reg_user_mr);

int hyv_ibv_dereg_mr(struct ib_mr *ibmr)
{
	struct hyv_device *dev = ibdev_to_hyv(ibmr->device);
	struct hyv_mr *mr = ibmr_to_hyv(ibmr);
	int ret, hret;
	unsigned long i;

	dprint(DBG_IBV, "\n");

	ret = hyv_ibv_dereg_mrX(&dev->vg->vq_hcall,
				HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
				GFP_KERNEL, &hret, mr->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not deregister mr on host\n");
		return ret ? ret : hret;
	}

	/* umem[0] is registered memory, rest udata translations */
	for (i = 0; i < mr->n_umem + 1; i++) {
		hyv_unpin_user_mem(mr->umem[i]);
	}
	kfree(mr->umem);
	kfree(mr);
	return 0;
}
EXPORT_SYMBOL(hyv_ibv_dereg_mr);

int hyv_ibv_post_send_null(struct ib_qp *ibqp)
{
	struct hyv_device *dev = ibdev_to_hyv(ibqp->device);
	struct hyv_qp *qp = ibqp_to_hyv(ibqp);
	int ret, hret;

	dprint(DBG_IBV, "\n");

	ret = hyv_ibv_post_send_nullX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, qp->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not post send null on host!\n");
		return ret ? ret : hret;
	}

	return 0;
}
EXPORT_SYMBOL(hyv_ibv_post_send_null);

int hyv_ibv_mmap(struct ib_ucontext *ibuctx, struct vm_area_struct *vma)
{
	struct hyv_device *dev = ibdev_to_hyv(ibuctx->device);
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);
	uint32_t key = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	struct hyv_mmap *gmm;
	int ret;
	hyv_mmap_result res;
	unsigned long phys_addr;
	unsigned long prot;

	dprint(DBG_IBV, "pgoff 0x%lx key 0x%x len %lu\n", vma->vm_pgoff, key,
	       size);

	gmm = hyv_mmap_get(ibuctx, key);
	if (!gmm) {
		dprint(DBG_ON, "mmap get failed\n");
		ret = -EINVAL;
		goto fail;
	}

	/* map on host */
	phys_addr = virt_to_phys(gmm->addr);
	WARN_ON(gmm->size != size);

	ret = hyv_mmap(&dev->vg->vq_hcall,
		       HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
		       GFP_KERNEL, &res, uctx->host_handle, phys_addr,
		       gmm->size, vma->vm_flags, vma->vm_pgoff);
	if (ret || res.mmap_handle < 0) {
		dprint(DBG_ON, "could not mmap on host\n");
		ret = ret ? ret : res.mmap_handle;
		goto fail;
	}
	gmm->host_handle = res.mmap_handle;

#ifdef CONFIG_X86
	if (res.pgprot & _PAGE_CACHE_WC) {
		dprint(DBG_IBV, "write combine\n");
		set_memory_wc((unsigned long)gmm->addr, size >> PAGE_SHIFT);
	} else if (res.pgprot & _PAGE_CACHE_UC_MINUS) {
		dprint(DBG_IBV, "UC-\n");
		set_memory_uc((unsigned long)gmm->addr, size >> PAGE_SHIFT);
	} else if (res.pgprot & _PAGE_CACHE_WB) {
		/* nothing to do here */
		dprint(DBG_IBV, "write back\n");
	}
	/* remove page cache prot */
	prot = pgprot_val(vma->vm_page_prot) & ~_PAGE_CACHE_MASK;
	/* take page cache prot from host */
	prot = prot | (res.pgprot & _PAGE_CACHE_MASK);
	vma->vm_page_prot = __pgprot(prot);
#endif
	ret = remap_pfn_range(vma, vma->vm_start, phys_addr >> PAGE_SHIFT, size,
			      vma->vm_page_prot);
	if (ret) {
		dprint(DBG_ON, "could not remap pfn range\n");
		goto fail;
	}
	gmm->mapped = true;

fail:
	return ret;
}
EXPORT_SYMBOL(hyv_ibv_mmap);
