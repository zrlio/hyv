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

#include "hyv.h"
#include "virtio_hyv.h"
#include "virtio_hyv_debug.h"

#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>

#define GUEST
#include <hyv_hypercall.h>

struct hyv_mr_cache
{
	DECLARE_HASHTABLE(map, 12);
	spinlock_t lock;
};

#define DMA_MR_BITS 12
#define DMA_MR_SIZE (1 << DMA_MR_BITS)
#define DMA_MR_MASK ~((1 << DMA_MR_BITS) - 1)

static int map_dma_sges(struct hyv_pd *pd, struct ib_sge *sg_list,
			uint32_t num_sge)
{
	struct ib_device *ibdev = pd->ibpd.device;
	struct hyv_mr_cache *cache = pd->dma_mr_cache;

	uint32_t i;
	for (i = 0; i < num_sge; i++) {
		if (sg_list[i].lkey == ibdev->local_dma_lkey) {
			// TODO: copy the send_wr linked list out
			struct hyv_mr *mr;
			unsigned long addr = sg_list[i].addr;
			unsigned long offset = addr & ~DMA_MR_MASK;
			u64 size = sg_list[i].length;
			u64 iova = addr & DMA_MR_MASK;
			bool found = false;
			unsigned long flags;

			dprint(DBG_KVERBS, "addr = 0x%lx, size = %u\n", addr,
			       sg_list[i].length);

			spin_lock_irqsave(&cache->lock, flags);
			hash_for_each_possible(cache->map, mr, node, iova)
			{
				if (mr->iova == iova &&
				    mr->size - offset >= size) {
					found = true;
					break;
				}
			}
			spin_unlock_irqrestore(&cache->lock, flags);

			if (!found) {
				struct ib_mr *ibmr;
				struct ib_phys_buf phys_buf_array;
				u64 reg_size = max_t(
				    u64, ALIGN(size + offset, DMA_MR_SIZE),
				    DMA_MR_SIZE);

				/* this only works for pages at the end of phys
				 * memory */
				/* while (!pfn_valid(((iova + reg_size) >>
				 * PAGE_SHIFT) - 1)) {
				 */
				/*     reg_size >>= 1; */
				/*     if (reg_size == 0) { */
				/*         break; */
				/*     } */
				/* } */

				if (reg_size < size + offset) {
					dprint(
					    DBG_ON,
					    "pfn does not seem to be valid\n");
					return -EINVAL;
				}

				dprint(DBG_KVERBS,
				       "register: addr = 0x%llx, size = %llu\n",
				       iova, reg_size);

				phys_buf_array.addr = iova;
				/* size is multiple of DMA_MR_SIZE */
				phys_buf_array.size = reg_size;

				ibmr = ib_reg_phys_mr(
				    &pd->ibpd, &phys_buf_array, 1,
				    IB_ACCESS_LOCAL_WRITE |
					IB_ACCESS_REMOTE_WRITE,
				    &iova);
				if (IS_ERR(ibmr)) {
					dprint(DBG_ON,
					       "could not register phys mem\n");
					return PTR_ERR(ibmr);
				}
				mr = ibmr_to_hyv(ibmr);

				mr->iova = iova;
				mr->size = phys_buf_array.size;

				/* worst case scenario is someone registering
				 * the same
				 * memory in parallel */
				spin_lock_irqsave(&cache->lock, flags);
				hash_add(cache->map, &mr->node, iova);
				spin_unlock_irqrestore(&cache->lock, flags);
			}

			sg_list[i].lkey = mr->ibmr.lkey;
		}
	}

	return 0;
}

int hyv_kverbs_prepare_post_send(struct ib_qp *qp, struct ib_send_wr *send_wr,
				 struct ib_send_wr **bad_send_wr)
{
	struct hyv_pd *pd = ibpd_to_hyv(qp->pd);
	int ret = 0;
	struct ib_send_wr *iter_send_wr;

	dprint(DBG_KVERBS, "\n");

	for (iter_send_wr = send_wr; iter_send_wr;
	     iter_send_wr = iter_send_wr->next) {
		if (!(iter_send_wr->send_flags & IB_SEND_INLINE)) {
			ret = map_dma_sges(pd, iter_send_wr->sg_list,
					   iter_send_wr->num_sge);
			if (ret) {
				*bad_send_wr = iter_send_wr;
				break;
			}
		}
	}

	return ret;
}
EXPORT_SYMBOL(hyv_kverbs_prepare_post_send);

int hyv_kverbs_prepare_post_recv(struct ib_qp *qp, struct ib_recv_wr *recv_wr,
				 struct ib_recv_wr **bad_recv_wr)
{
	struct hyv_pd *pd = ibpd_to_hyv(qp->pd);
	int ret = 0;
	struct ib_recv_wr *iter_recv_wr;

	dprint(DBG_KVERBS, "\n");

	for (iter_recv_wr = recv_wr; iter_recv_wr;
	     iter_recv_wr = iter_recv_wr->next) {
		ret = map_dma_sges(pd, iter_recv_wr->sg_list,
				   iter_recv_wr->num_sge);
		if (ret) {
			*bad_recv_wr = iter_recv_wr;
			break;
		}
	}

	return ret;
}
EXPORT_SYMBOL(hyv_kverbs_prepare_post_recv);

int hyv_kverbs_init_pd(struct ib_pd *ibpd)
{
	struct hyv_pd *pd = ibpd_to_hyv(ibpd);

	dprint(DBG_KVERBS, "\n");

	pd->dma_mr_cache = kmalloc(sizeof(*pd->dma_mr_cache), GFP_KERNEL);

	spin_lock_init(&pd->dma_mr_cache->lock);
	hash_init(pd->dma_mr_cache->map);

	return 0;
}
EXPORT_SYMBOL(hyv_kverbs_init_pd);

// XXX: merge with hyv_ibv.c
#define UDATA_ARG(udata) udata, (sizeof(*udata) + udata->in + udata->out)

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

struct ib_mr *hyv_ibv_reg_phys_mr(struct ib_pd *ibpd,
				  struct ib_phys_buf *phys_buf_array,
				  int num_phys_buf, int access, u64 *iova_start,
				  struct ib_udata *ibudata)
{
	struct hyv_device *dev = ibdev_to_hyv(ibpd->device);
	struct hyv_pd *pd = ibpd_to_hyv(ibpd);
	struct hyv_mr *mr;
	hyv_reg_user_mr_result res;
	hyv_user_mem_chunk *umem_chunks;
	hyv_udata_translate *udata_translate;
	uint32_t i;
	unsigned long size;
	hyv_udata *udata;
	bool write;
	int ret;

	dprint(DBG_KVERBS, "\n");

	write = !!(access & ~IB_ACCESS_REMOTE_READ);

	mr = kmalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		dprint(DBG_ON, "could not allocate mr\n");
		ret = -ENOMEM;
		goto fail;
	}

	size = 0;
	umem_chunks = kmalloc(sizeof(*umem_chunks) * num_phys_buf, GFP_KERNEL);
	if (!umem_chunks) {
		dprint(DBG_ON, "could not alloc umem chunks\n");
		ret = -ENOMEM;
		goto fail_mr;
	}

	for (i = 0; i < num_phys_buf; i++) {
		umem_chunks[i].addr = phys_buf_array[i].addr;
		umem_chunks[i].size = phys_buf_array[i].size;
		size += umem_chunks[i].size;
	}

	/* we don't need umem -> no pages to pin in the kernel */
	mr->umem = NULL;
	mr->n_umem = 0;

	udata = udata_create(ibudata);
	if (IS_ERR(udata)) {
		ret = PTR_ERR(udata);
		goto fail_umem_chunks;
	}

	udata_translate = kzalloc(sizeof(*udata_translate), GFP_KERNEL);
	if (!udata_translate) {
		dprint(DBG_ON, "could not alloc udata translate\n");
		ret = -ENOMEM;
		goto fail_umem_chunks;
	}

	ret = hyv_ibv_reg_user_mrX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &res, pd->host_handle, *iova_start, size, access,
	    umem_chunks, num_phys_buf * sizeof(*umem_chunks), UDATA_ARG(udata),
	    udata_translate, sizeof(*udata_translate));
	if (ret || res.mr_handle < 0) {
		dprint(DBG_ON, "could not reg user mr on host\n");
		ret = ret ? ret : res.mr_handle;
		goto fail_udata_translate;
	}
	mr->access = access;
	mr->host_handle = res.mr_handle;
	mr->ibmr.lkey = res.lkey;
	mr->ibmr.rkey = res.rkey;

	kfree(udata_translate);
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
	kfree(udata_translate);
fail_umem_chunks:
	kfree(umem_chunks);
fail_mr:
	kfree(mr);
fail:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(hyv_ibv_reg_phys_mr);

int hyv_kverbs_mmap(struct ib_ucontext *ibuctx, struct hyv_mmap *gmm,
		    unsigned long vm_flags)
{
	struct hyv_device *dev = ibdev_to_hyv(ibuctx->device);
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);
	hyv_mmap_result res;
	int ret;

	dprint(DBG_KVERBS, "\n");

	vm_flags |= VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	if (vm_flags & VM_SHARED) {
		vm_flags |= VM_MAYSHARE;
	}

	ret = hyv_mmap(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &res, uctx->host_handle, virt_to_phys(gmm->addr),
	    gmm->size, vm_flags, gmm->key >> PAGE_SHIFT);
	if (ret || res.mmap_handle < 0) {
		dprint(DBG_ON, "could not mmap on host\n");
		ret = ret ? ret : res.mmap_handle;
		goto fail;
	}
	gmm->host_handle = res.mmap_handle;
	gmm->mapped = true;

	return 0;
fail:
	return ret;
}
EXPORT_SYMBOL(hyv_kverbs_mmap);
