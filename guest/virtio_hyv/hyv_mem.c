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
#include <linux/spinlock.h>
#include <linux/mm_types.h>

#include <hypercall_guest.h>
#include <hyv_hypercall.h>

#include "virtio_hyv.h"
#include "virtio_hyv_debug.h"

#include <hyv.h>

struct hyv_user_mem
{
	struct page **pages;
	unsigned long n_pages;
};

struct hyv_mmap *hyv_mmap_alloc(uint32_t size, uint32_t key)
{
	struct hyv_mmap *gmm;
	void *addr;
	int ret;

	dprint(DBG_MEM, "\n");

	gmm = kzalloc(sizeof(*gmm), GFP_KERNEL);
	if (!gmm) {
		dprint(DBG_ON, "could not allocate mmap struct\n");
		ret = -ENOMEM;
		goto fail;
	}

	addr = alloc_pages_exact(size, GFP_KERNEL);
	if (!addr) {
		dprint(DBG_ON, "could not allocate pages\n");
		ret = -ENOMEM;
		goto fail_gmm;
	}
	gmm->addr = addr;
	gmm->key = key;
	gmm->size = size;
	gmm->mapped = false;

	return gmm;
fail_gmm:
	kfree(gmm);
fail:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(hyv_mmap_alloc);

struct hyv_mmap *hyv_mmap_prepare(struct ib_ucontext *ibuctx, uint32_t size,
				  uint32_t key)
{
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);
	struct hyv_mmap *gmm;

	dprint(DBG_MEM, "\n");

	gmm = hyv_mmap_alloc(size, key);
	if (IS_ERR(gmm)) {
		dprint(DBG_ON, "could not alloc mmap struct\n");
		return ERR_PTR(-ENOMEM);
	}

	spin_lock(&uctx->mmap_lock);
	list_add_tail(&gmm->list, &uctx->mmap_list);
	spin_unlock(&uctx->mmap_lock);

	return gmm;
}
EXPORT_SYMBOL(hyv_mmap_prepare);

struct hyv_mmap *hyv_mmap_get(struct ib_ucontext *ibuctx, uint32_t key)
{
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);
	struct hyv_mmap *mm;

	dprint(DBG_MEM, "\n");

	spin_lock(&uctx->mmap_lock);
	list_for_each_entry(mm, &uctx->mmap_list, list)
	{
		if (mm->key == key) {
			list_del(&mm->list);
			spin_unlock(&uctx->mmap_lock);
			return mm;
		}
	}
	spin_unlock(&uctx->mmap_lock);

	return NULL;
}

void hyv_mmap_unprepare(struct ib_ucontext *ibuctx, struct hyv_mmap *mm)
{
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);

	spin_lock(&uctx->mmap_lock);
	list_del(&mm->list);
	spin_unlock(&uctx->mmap_lock);

	hyv_unmap(ibuctx, mm);
}
EXPORT_SYMBOL(hyv_mmap_unprepare);

int hyv_unmap(struct ib_ucontext *ibuctx, struct hyv_mmap *mm)
{
	struct hyv_device *dev = ibdev_to_hyv(ibuctx->device);
	int ret = 0, hret;

	dprint(DBG_MEM, "\n");

	if (mm->mapped) {
		ret = hyv_munmap(&dev->vg->vq_hcall,
				 HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
				 GFP_KERNEL, &hret, mm->host_handle);
		if (ret || hret) {
			dprint(DBG_ON, "could not unmap on host\n");
			ret = ret ? ret : hret;
		}
	}

	free_pages_exact(mm->addr, mm->size);
	kfree(mm);
	return ret;
}
EXPORT_SYMBOL(hyv_unmap);

struct hyv_user_mem *hyv_pin_user_mem(unsigned long va, unsigned long size,
				      hyv_user_mem_chunk **chunks,
				      unsigned long *n_chunks, bool write)
{
	struct hyv_user_mem *umem;
	unsigned long i, offset, cur_va;
	unsigned long n_pages, pages_pinned = 0;
	unsigned long cur_chunk;
	unsigned long pin_limit;
	struct mm_struct *mm = current->mm;
	hyv_user_mem_chunk *chunk_tmp = NULL;
	struct page **pages;
	int ret;

	dprint(DBG_MEM, "va: 0x%lx, size: %lu, write: %d\n", va, size, write);

	offset = va & ~PAGE_MASK;
	n_pages = PAGE_ALIGN(size + offset) >> PAGE_SHIFT;

	dprint(DBG_MEM, "n_pages: %lu, offset: 0x%lx\n", n_pages, offset);

	if (n_pages == 0) {
		ret = -EINVAL;
		goto fail;
	}

	pages = vmalloc(sizeof(*pages) * n_pages);
	if (!pages) {
		dprint(DBG_ON, "could not allocate page array\n");
		ret = -ENOMEM;
		goto fail;
	}

	down_write(&mm->mmap_sem);
	pin_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if ((n_pages + mm->pinned_vm) > pin_limit && !capable(CAP_IPC_LOCK)) {
		dprint(DBG_ON, "cannot lock memory\n");
		ret = -ENOMEM;
		goto fail_get_user;
	}

	for (cur_va = va; n_pages != pages_pinned;
	     cur_va += (ret * PAGE_SIZE)) {
		ret =
		    get_user_pages(current, mm, cur_va, n_pages - pages_pinned,
				   1, !write, pages + pages_pinned, NULL);
		if (ret <= 0) {
			dprint(DBG_ON, "could not pin pages (%d)\n", ret);
			ret = -EFAULT;
			goto fail_get_user;
		}
		pages_pinned += ret;
	}

	if (chunks) {
		*n_chunks = 1;
		for (i = 1; i < n_pages; ++i) {
			if (page_to_pfn(pages[i]) !=
			    page_to_pfn(pages[i - 1]) + 1) {
				(*n_chunks)++;
			}
		}

		dprint(DBG_MEM, "n_chunks: %lu\n", *n_chunks);

		chunk_tmp = kmalloc(sizeof(*chunk_tmp) * *n_chunks, GFP_KERNEL);
		if (!chunk_tmp) {
			dprint(DBG_ON, "could not allocate chunks!\n");
			ret = -ENOMEM;
			goto fail_get_user;
		}

		chunk_tmp[0].addr = page_to_phys(pages[0]) + offset;
		if (n_pages == 1) {
			chunk_tmp[0].size = size;
		} else {
			unsigned long end_offset;

			chunk_tmp[0].size = PAGE_SIZE - offset;
			for (i = 1, cur_chunk = 0; i < n_pages; ++i) {
				if (page_to_pfn(pages[i]) !=
				    page_to_pfn(pages[i - 1]) + 1) {
					cur_chunk++;
					chunk_tmp[cur_chunk].addr =
					    page_to_phys(pages[i]);
					chunk_tmp[cur_chunk].size = PAGE_SIZE;
				} else {
					chunk_tmp[cur_chunk].size += PAGE_SIZE;
				}
			}

			/* cut last chunk to real size */
			end_offset = ((size - chunk_tmp[0].size) & ~PAGE_MASK);
			if (end_offset) {
				chunk_tmp[cur_chunk].size -=
				    PAGE_SIZE - end_offset;
			}
		}

#if DBG_MEM &DPRINT_MASK
		for (i = 0; i < *n_chunks; i++) {
			dprint(DBG_MEM, "-- chunk[%lu] --\n", i);
			dprint(DBG_MEM, "phys_addr: 0x%llx\n",
			       chunk_tmp[i].addr);
			dprint(DBG_MEM, "size: %llu\n", chunk_tmp[i].size);
		}
#endif

		*chunks = chunk_tmp;
	}

	umem = kmalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem) {
		dprint(DBG_ON, "could not allocate user mem struct\n");
		ret = -ENOMEM;
		goto fail_chunk;
	}
	umem->pages = pages;
	umem->n_pages = n_pages;

	/* is it guaranteed that nobody else is changing this while are in the
	 * mmap_sem? */
	mm->pinned_vm += n_pages;
	up_write(&mm->mmap_sem);

	return umem;
fail_chunk:
	kfree(chunk_tmp);
fail_get_user:
	up_write(&mm->mmap_sem);
	for (i = 0; i < pages_pinned; i++) {
		put_page(pages[i]);
	}
	vfree(pages);
fail:
	return ERR_PTR(ret);
}

void hyv_unpin_user_mem(struct hyv_user_mem *umem)
{
	unsigned long i;
	struct mm_struct *mm = current->mm;

	dprint(DBG_MEM, "\n");

	/* the process might be already terminated */
	if (mm) {
		down_write(&mm->mmap_sem);
		mm->pinned_vm -= umem->n_pages;
		up_write(&mm->mmap_sem);
	}

	for (i = 0; i < umem->n_pages; i++) {
		put_page(umem->pages[i]);
	}
	vfree(umem->pages);
	kfree(umem);
}
