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

#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/compiler.h>
#include <asm/pgtable.h>

#include <linux/module.h>
#include <rdma/ib_umem.h>

#include <hypercall_host.h>
#include <hyv_hypercall.h>

#include <object_map.h>

#include "vhost_mem.h"

#include "vhost_hyv.h"
#include "vhost_hyv_debug.h"
#include "vhost_hyv_ibv.h"

#include "vhost_hyv_mem.h"

static int (*_do_munmap)(struct mm_struct *, unsigned long, size_t);
static unsigned long (*_mmap_region)(struct file *, unsigned long,
				     unsigned long, vm_flags_t, unsigned long);

static struct
{
	struct module *ib_core_mod;
	const struct kernel_symbol *ib_core_syms;
	const struct kernel_symbol *vhost_hyv_syms;
} ib_umem_get_replace;

struct vhost_hyv_umem
{
	unsigned long user_va;

	hyv_user_mem_chunk *gchunk;
	unsigned long n_chunks;
	bool done;
};

static struct ib_umem *vhost_hyv_ib_umem_get(struct ib_ucontext *context,
					     unsigned long addr, size_t size,
					     int access, int dmasync);

int vhost_mem_init(void)
{
	struct module *ib_core_mod, *vhost_hyv_mod;
	struct kernel_symbol *ib_core_syms, *vhost_hyv_syms;
	unsigned long i;
	int ret;

	_do_munmap = (void *)kallsyms_lookup_name("do_munmap");
	if (!_do_munmap) {
		dprint(DBG_ON, "Could not find symbol do_munmap!\n");
		ret = -ENOENT;
		goto fail;
	}
	_mmap_region = (void *)kallsyms_lookup_name("mmap_region");
	if (!_mmap_region) {
		dprint(DBG_ON, "Could not find symbol mmap_region!\n");
		ret = -ENOENT;
		goto fail;
	}

	mutex_lock(&module_mutex);
	ib_core_mod = find_module("ib_core");
	mutex_unlock(&module_mutex);
	if (!ib_core_mod) {
		dprint(DBG_ON, "Could not find module ib_core\n");
		ret = -ENOENT;
		goto fail;
	}
	/* we already have a dependency to ib_core so no need to get the
	 * module here */

	/* replace ib_umem_get with our version */
	for (i = 0; i < ib_core_mod->num_syms; i++) {
		if (strcmp("ib_umem_get", ib_core_mod->syms[i].name) == 0) {
			break;
		}
	}

	if (i == ib_core_mod->num_syms) {
		dprint(DBG_ON, "could not find ib_umem_get symbol\n");
		ret = -ENOENT;
		goto fail;
	}

	ib_core_syms =
	    kmalloc(sizeof(*ib_core_syms) * ib_core_mod->num_syms, GFP_KERNEL);
	if (!ib_core_syms) {
		dprint(DBG_ON, "could not allocate symbol table\n");
		ret = -ENOMEM;
		goto fail;
	}
	memcpy(ib_core_syms, ib_core_mod->syms,
	       sizeof(*ib_core_syms) * ib_core_mod->num_syms);
	/* rename ib_umem_get */
	ib_core_syms[i].name = "__ib_umem_get";

	vhost_hyv_mod = THIS_MODULE;

	vhost_hyv_syms =
	    kmalloc(sizeof(*vhost_hyv_syms) * (vhost_hyv_mod->num_syms + 1),
		    GFP_KERNEL);
	if (!vhost_hyv_syms) {
		dprint(DBG_ON, "could not alloc hyv syms\n");
		ret = -ENOMEM;
		goto fail_ib_core_syms;
	}

	vhost_hyv_syms[vhost_hyv_mod->num_syms].name = "ib_umem_get";
	vhost_hyv_syms[vhost_hyv_mod->num_syms].value =
	    (unsigned long)&vhost_hyv_ib_umem_get;

	mutex_lock(&module_mutex);
	/* add ib_umem_get to vhost_hyv exported symbols */
	ib_umem_get_replace.vhost_hyv_syms = vhost_hyv_mod->syms;
	vhost_hyv_mod->syms = vhost_hyv_syms;
	vhost_hyv_mod->num_syms++;

	/* replace symbols of ib_core with renamed ib_umem_get */
	ib_umem_get_replace.ib_core_mod = ib_core_mod;
	ib_umem_get_replace.ib_core_syms = ib_core_mod->syms;
	ib_core_mod->syms = ib_core_syms;
	mutex_unlock(&module_mutex);

	return 0;
fail_ib_core_syms:
	kfree(ib_core_syms);
fail:
	return ret;
}

void vhost_mem_exit(void)
{
	struct module *vhost_hyv_mod;
	const struct kernel_symbol *ib_core_syms, *vhost_hyv_syms;

	/* restore ib_core syms */
	mutex_lock(&module_mutex);
	ib_core_syms = ib_umem_get_replace.ib_core_mod->syms;
	ib_umem_get_replace.ib_core_mod->syms =
	    ib_umem_get_replace.ib_core_syms;
	kfree(ib_core_syms);

	vhost_hyv_mod = THIS_MODULE;
	vhost_hyv_syms = vhost_hyv_mod->syms;
	vhost_hyv_mod->num_syms--;
	vhost_hyv_mod->syms = ib_umem_get_replace.vhost_hyv_syms;
	kfree(vhost_hyv_syms);
	mutex_unlock(&module_mutex);
}

void vhost_hyv_mmap_release(struct object *obj)
{
	struct vhost_hyv_mmap *mmap =
	    container_of(obj, struct vhost_hyv_mmap, hdr);

	dprint(DBG_MM, "\n");

	/* restore mapping */
	if (vhost_hyv_munmap(mmap)) {
		dprint(DBG_ON, "unmap failed!\n");
	}
	object_put(&mmap->uctx->hdr, &vhost_hyv_ucontext_release);
	kfree(mmap);
}

int vhost_hyv_mmap_wrapper(struct file *f, struct vm_area_struct *vma)
{
	struct ib_ucontext *ibuctx = f->private_data;
	int ret;

	dprint(DBG_MM, "\n");

	ret = ibuctx->device->mmap(ibuctx, vma);
	if (ret) {
		dprint(DBG_ON, "device mmap failed!\n");
		return ret;
	}

	return 0;
}

int vhost_hyv_remap(struct vhost_hyv_ucontext *uctx,
		    struct vhost_hyv_mmap *gmmap, uint64_t gpa, size_t size,
		    vm_flags_t vm_flags, unsigned long vm_pgoff,
		    pgprot_t *pgprot)
{
	struct iovec hvm;
	unsigned long hva, remapped_hva, pfn;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int ret;

	dprint(DBG_MM, "\n");

	if (vhost_gpm_to_hvm(&uctx->gdev->vg->vdev, gpa, size, &hvm, 1) != 1 ||
	    hvm.iov_len < size) {
		dprint(DBG_ON, "could not translate gpm to hvm\n");
		ret = -EFAULT;
		goto fail;
	}
	hva = (unsigned long)hvm.iov_base;
	if (!PAGE_ALIGNED(hva) || !PAGE_ALIGNED(size)) {
		ret = -EFAULT;
		dprint(DBG_ON, "not page aligned\n");
		goto fail;
	}
	gmmap->hva = hva;
	gmmap->size = size;

	dprint(DBG_MM, "Translate gpa 0x%llx to hva 0x%lx\n", gpa, hva);

	down_write(&mm->mmap_sem);
	vma = find_vma(mm, hva);
	if (!vma) {
		dprint(DBG_ON, "unable to find vma\n");
		ret = -EFAULT;
	}
	if (hva < vma->vm_start || hva + size > vma->vm_end) {
		/* probably a failed merge of a previous remapping! */
		dprint(DBG_ON, "not in vma [0x%lx, 0x%lx]: %lx (%lx)!\n",
		       vma->vm_start, vma->vm_end, hva, size);
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	/* save properties for restore */
	gmmap->vm_file = vma->vm_file;
	gmmap->vm_flags = vma->vm_flags;
	gmmap->vm_pgoff = vma->vm_pgoff + ((hva - vma->vm_start) >> PAGE_SHIFT);

	ret = _do_munmap(mm, hva, size);
	if (ret) {
		dprint(DBG_ON, "unmap failed!\n");
		goto fail_mmap_sem;
	}

	if (vm_flags & VM_DENYWRITE) {
		dprint(DBG_ON, "deny write\n");
		goto fail_unmap;
	}

	remapped_hva = _mmap_region(uctx->f, hva, size, vm_flags, vm_pgoff);
	if (IS_ERR_VALUE(remapped_hva)) {
		dprint(DBG_ON, "mmap failed!\n");
		ret = -EFAULT;
		goto fail_unmap;
	} else if (remapped_hva != hva) {
		dprint(DBG_ON, "wrong virtual address!\n");
		ret = _do_munmap(mm, remapped_hva, size);
		if (ret) {
			send_sig(SIGKILL, current, 0);
			ret = -EFAULT;
			goto fail_unmap;
		}
	}

	vma = find_vma(mm, hva);
	BUG_ON(!vma);
	*pgprot = vma->vm_page_prot;
	if (vma->vm_start != hva) {
		dprint(DBG_ON, "got merged!\n");
		BUG();
	}

	gmmap->type = VHOST_HYV_MMAP_NORMAL;

	/* set vma pfn and check for valid pfns */
	if (vma->vm_flags & VM_PFNMAP) {
		ret = follow_pfn(vma, vma->vm_start, &pfn);
		if (ret) {
			dprint(DBG_ON, "could not follow pfn\n");
			/* something is clearly wrong */
			BUG();
		}

		vma->vm_pgoff = pfn;

		if (pfn_valid(pfn)) {
			unsigned long n_pages = vma_pages(vma);
			unsigned long i;
			struct page *page;

			vma->vm_pgoff = pfn;
			gmmap->pfn = pfn;

			dprint(DBG_MM, "valid pfn in PFNMAP (n_pages: %lu)\n",
			       n_pages);

			/* XXX: assume _one_ higher order page! */
			page = pfn_to_page(pfn);
			if (page_count(page)) {
				/* we get the (higher-order) page such that it
				 * is not freed
				 * before we restore the mapping */
				dprint(DBG_MM, "get page\n");
				get_page(page);
			} else {
				dprint(DBG_ON, "zero page count?\n");
				BUG();
			}

			/* XXX: assume contiguous mem
			 * we might want to walk the pagetable instead */
			for (i = 0; i < n_pages; i++, pfn++) {
				page = pfn_to_page(pfn);
				BUG_ON(!pfn_valid(pfn));
				dprint(DBG_MM,
				       "Set page reserved: pfn = 0x%lx\n", pfn);
				SetPageReserved(page);
			}
			/* we need this to unset reserved flag */
			gmmap->type = VHOST_HYV_MMAP_PFNMAP;
		}
	}
	up_write(&mm->mmap_sem);

	return 0;
fail_unmap:
	remapped_hva = _mmap_region(gmmap->vm_file, hva, size, gmmap->vm_flags,
				    gmmap->vm_pgoff);
	if (remapped_hva != hva) {
		dprint(DBG_ON, "recover failed remap failed\n");
		/* kill the process */
		send_sig(SIGKILL, current, 0);
		ret = -EFAULT;
	}
fail_mmap_sem:
	up_write(&mm->mmap_sem);
fail:
	return ret;
}

DEF_HYPERCALL(hyv_mmap, hyv_mmap_result, MMAP_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_ucontext *uctx;
	struct vhost_hyv_mmap *mmap;
	hyv_mmap_result res;
	int ret;
	pgprot_t pgprot;

	dprint(DBG_MM, "\n");

	uctx = object_map_id_get_entry(&vg->uctxs, struct vhost_hyv_ucontext,
				       hdr, uctx_handle);
	if (!uctx) {
		dprint(DBG_ON, "no uctx with this id!\n");
		ret = -EINVAL;
		goto fail;
	}

	mmap = kmalloc(sizeof(*mmap), GFP_KERNEL);
	if (!mmap) {
		dprint(DBG_ON, "could not allocate mmap obj\n");
		ret = -ENOMEM;
		goto fail_get;
	}
	mmap->uctx = uctx;

	ret = object_map_add(&vg->mmaps, &uctx->mmaps, &mmap->hdr);
	if (ret < 0) {
		goto fail_mmap;
	}
	res.mmap_handle = ret;

	ret = vhost_hyv_remap(uctx, mmap, phys_addr, size, vm_flags, vm_pgoff,
			      &pgprot);
	if (ret) {
		goto fail_add;
	}
	res.pgprot = pgprot_val(pgprot);

	return res;
fail_add:
	object_map_del(&mmap->hdr, &vhost_hyv_mmap_release);
	return (hyv_mmap_result) { ret, 0 };

fail_mmap:
	kfree(mmap);
fail_get:
	object_put(&uctx->hdr, &vhost_hyv_ucontext_release);
fail:
	return (hyv_mmap_result) { ret, 0 };
}

int vhost_hyv_munmap(struct vhost_hyv_mmap *gmmap)
{
	struct mm_struct *mm = current->mm;
	int ret;
	unsigned long remapped_hva;

	dprint(DBG_MM, "\n");

	if (!mm) {
		/* qemu process is dead or called with wrong context */
		dprint(DBG_ON, "invalid context!\n");
		return -EINVAL;
	}

	down_write(&mm->mmap_sem);
	ret = _do_munmap(mm, gmmap->hva, gmmap->size);
	if (ret) {
		dprint(DBG_ON, "unmap failed!\n");
		goto fail_mmap_sem;
	}

	remapped_hva = _mmap_region(gmmap->vm_file, gmmap->hva, gmmap->size,
				    gmmap->vm_flags, gmmap->vm_pgoff);
	if (remapped_hva != gmmap->hva) {
		dprint(DBG_ON, "mmap failed\n");
		/* kill the process */
		send_sig(SIGKILL, current, 0);
	}
	up_write(&mm->mmap_sem);

	if (gmmap->type == VHOST_HYV_MMAP_PFNMAP) {
		unsigned long i;
		unsigned long n_pages = gmmap->size >> PAGE_SHIFT;
		unsigned long pfn = gmmap->pfn;
		struct page *page;

		page = pfn_to_page(pfn);
		if (put_page_testzero(page)) {
			dprint(DBG_ON,
			       "it's now our job to free these pages!\n");
			/* XXX again we assume _one_ higher order page see remap
			 * function */
			__free_pages(page, get_order(gmmap->size));
		}

		/* XXX again for now we assume this is contiguous */
		for (i = 0; i < n_pages; i++, pfn++) {
			page = pfn_to_page(pfn);
			dprint(DBG_MM, "Clear page reserved: pfn = 0x%lx\n",
			       pfn);
			ClearPageReserved(page);
		}
	}

	return 0;
fail_mmap_sem:
	up_write(&mm->mmap_sem);
	return ret;
}

DEF_HYPERCALL(hyv_munmap, __s32, MUNMAP_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);

	return object_map_id_del(&vg->mmaps, mmap_handle,
				 &vhost_hyv_mmap_release);
}

struct vhost_hyv_umem **
vhost_hyv_ib_umem_prepare(struct vhost_hyv_ucontext *uctx,
			  unsigned long user_va, hyv_user_mem_chunk *gchunk,
			  unsigned long n_chunks)
{
	struct vhost_hyv_umem *umem;
	unsigned long i;
	int ret;

	umem = kmalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem) {
		dprint(DBG_ON, "could not allocate umem\n");
		ret = -ENOMEM;
		goto fail;
	}

	umem->user_va = user_va;
	umem->gchunk = gchunk;
	umem->n_chunks = n_chunks;
	umem->done = false;

	dprint(DBG_MM, "user_va: 0x%lx\n", user_va);

	spin_lock(&uctx->umem_map_lock);
	for (i = 0; i < uctx->umem_map_size; i++) {
		if (!uctx->umem_map[i]) {
			uctx->umem_map[i] = umem;
			break;
		}
	}
	spin_unlock(&uctx->umem_map_lock);

	if (i == uctx->umem_map_size) {
		dprint(DBG_ON, "umem map full!\n");
		ret = -ENOSPC;
		goto fail_umem;
	}

	return &uctx->umem_map[i];
fail_umem:
	kfree(umem);
fail:
	return ERR_PTR(ret);
}

int vhost_hyv_ib_umem_finish(struct vhost_hyv_umem **umem_entry)
{
	struct vhost_hyv_umem *umem = *umem_entry;
	bool done;

	BUG_ON(!umem);

	done = umem->done;
	if (!done) {
		dprint(DBG_ON, "umem (0x%lx) was not mapped\n", umem->user_va);
	}

	*umem_entry = NULL;
	kfree(umem);

	return done ? 0 : -EBUSY;
}

int vhost_hyv_ib_umem_finish_hva(struct vhost_hyv_ucontext *uctx,
				 unsigned long hva)
{
	unsigned int i;

	spin_lock(&uctx->umem_map_lock);
	for (i = 0; i < uctx->umem_map_size; i++) {
		if (uctx->umem_map[i] && uctx->umem_map[i]->user_va == hva) {
			break;
		}
	}
	spin_unlock(&uctx->umem_map_lock);

	if (i == uctx->umem_map_size) {
		dprint(DBG_ON, "no such entry\n");
		return -EINVAL;
	}

	return vhost_hyv_ib_umem_finish(&uctx->umem_map[i]);
}

#define IB_UMEM_MAX_PAGE_CHUNK                                                 \
	((PAGE_SIZE - offsetof(struct ib_umem_chunk, page_list)) /             \
	 ((void *)&((struct ib_umem_chunk *)0)->page_list[1] -                 \
	  (void *)&((struct ib_umem_chunk *)0)->page_list[0]))

static void __ib_umem_release(struct ib_device *dev, struct ib_umem *umem,
			      int dirty)
{
	struct ib_umem_chunk *chunk, *tmp;
	int i;

	list_for_each_entry_safe(chunk, tmp, &umem->chunk_list, list)
	{
		ib_dma_unmap_sg(dev, chunk->page_list, chunk->nents,
				DMA_BIDIRECTIONAL);
		for (i = 0; i < chunk->nents; ++i) {
			struct page *page = sg_page(&chunk->page_list[i]);

			if (umem->writable && dirty) {
				set_page_dirty_lock(page);
			}
			put_page(page);
		}

		kfree(chunk);
	}
}

static struct ib_umem *vhost_hyv_ib_umem_get(struct ib_ucontext *context,
					     unsigned long addr, size_t size,
					     int access, int dmasync)
{
	struct vhost_hyv_ucontext *uctx;
	struct vhost_hyv_umem *gumem;
	struct ib_umem *umem;
	struct page **page_list;
	struct ib_umem_chunk *chunk;
	unsigned long locked;
	unsigned long lock_limit;
	unsigned long cur_base;
	unsigned long n_pages_total;
	int ret;
	int off;
	unsigned long i;
	DEFINE_DMA_ATTRS(attrs);

	dprint(DBG_MM, "\n");

	if (context->closing != VHOST_HYV_MAGIC) {
		dprint(DBG_ON,
		       "not a virtual context -> call real ib_umem_get\n");
		return ib_umem_get(context, addr, size, access, dmasync);
	}

	uctx = list_first_entry(&context->rule_list, struct vhost_hyv_ucontext,
				ibuctx_list);

	spin_lock(&uctx->umem_map_lock);
	for (i = 0; i < uctx->umem_map_size; i++) {
		if (uctx->umem_map[i] && uctx->umem_map[i]->user_va == addr) {
			break;
		}
	}
	spin_unlock(&uctx->umem_map_lock);

	if (i == uctx->umem_map_size) {
		dprint(DBG_ON, "mapping was not prepared!\n");
		ret = -EINVAL;
		goto fail;
	}

	gumem = uctx->umem_map[i];

	if (dmasync) {
		dma_set_attr(DMA_ATTR_WRITE_BARRIER, &attrs);
	}

	if (!can_do_mlock()) {
		dprint(DBG_ON, "can not do mlock\n");
		ret = -EPERM;
		goto fail;
	}

	umem = kmalloc(sizeof *umem, GFP_KERNEL);
	if (!umem) {
		dprint(DBG_ON, "could not alloc umem\n");
		ret = -ENOMEM;
		goto fail;
	}

	umem->context = context;
	umem->length = size;
	umem->offset = addr & ~PAGE_MASK;
	umem->page_size = PAGE_SIZE;

	/*
	* We ask for writable memory if any access flags other than
	* "remote read" are set.  "Local write" and "remote write"
	* obviously require write access.  "Remote atomic" can do
	* things like fetch and add, which will modify memory, and
	* "MW bind" can change permissions by binding a window.
	*/
	umem->writable = !!(access & ~IB_ACCESS_REMOTE_READ);

	/* For now we don't have hugetlb support */
	umem->hugetlb = 0;

	INIT_LIST_HEAD(&umem->chunk_list);

	page_list = (struct page **)__get_free_page(GFP_KERNEL);
	if (!page_list) {
		dprint(DBG_ON, "could not get free page\n");
		ret = -ENOMEM;
		goto fail_umem;
	}

	n_pages_total = PAGE_ALIGN(size + umem->offset) >> PAGE_SHIFT;

	down_write(&current->mm->mmap_sem);

	locked = n_pages_total + current->mm->pinned_vm;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	if ((locked > lock_limit) && !capable(CAP_IPC_LOCK)) {
		dprint(DBG_ON, "cannot lock memory\n");
		ret = -ENOMEM;
		goto fail_get_pages;
	}

	dprint(DBG_MM, "total chunks: %lu\n", gumem->n_chunks);

	for (i = 0; i < gumem->n_chunks; i++) {
		struct iovec iov;
		uint64_t offset;
		unsigned long n_pages_chunk;
		hyv_user_mem_chunk *umem_chunks = gumem->gchunk;

		dprint(DBG_MM, "-- chunk[%lu] --\n", i);
		dprint(DBG_MM, "guest pa: 0x%llx\n", umem_chunks[i].addr);

		/* translate */
		ret =
		    vhost_gpm_to_hvm(&uctx->gdev->vg->vdev, umem_chunks[i].addr,
				     umem_chunks[i].size, &iov, 1);
		if (ret != 1) {
			dprint(DBG_ON, "could not translate mem chunk\n");
			ret = -EFAULT;
			goto fail_get_pages;
		}
		dprint(DBG_MM, "host va: 0x%p\n", iov.iov_base);

		/* check if translated chunk matches in size and page offset */
		dprint(DBG_MM, "size: %lu\n", iov.iov_len);
		if (iov.iov_len != umem_chunks[i].size) {
			dprint(DBG_ON, "size mismatch!?\n");
			ret = -EFAULT;
			goto fail_get_pages;
		}
		offset = (unsigned long)iov.iov_base & ~PAGE_MASK;
		dprint(DBG_MM, "offset: 0x%llx\n", offset);
		if (offset != (umem_chunks[i].addr & ~PAGE_MASK)) {
			dprint(DBG_ON, "offset mismatch\n");
			ret = -EFAULT;
			goto fail_get_pages;
		}

		/* chunks need to be contiguous on a page boundary
		 * i.e. except first chunk, addresses need to be page aligned.
		 * This also requires chunks to have page aligned sizes
		 * (except first and last)*/
		if (i != 0) {
			if (offset) {
				dprint(DBG_ON, "unaligned offset or size\n");
				ret = -EINVAL;
				goto fail_get_pages;
			}
			if (i != gumem->n_chunks - 1 &&
			    (iov.iov_len & ~PAGE_MASK)) {
				dprint(DBG_ON, "chunk size unaligned\n");
				ret = -EINVAL;
				goto fail_get_pages;
			}
		} else {
			/* first chunk */
			if (gumem->n_chunks > 1 &&
			    ((offset + iov.iov_len) & ~PAGE_MASK)) {
				dprint(DBG_ON, "first chunk unaligned\n");
				ret = -EINVAL;
				goto fail_get_pages;
			}
		}

		/* pin */
		n_pages_chunk = PAGE_ALIGN(iov.iov_len + offset) >> PAGE_SHIFT;
		dprint(DBG_MM, "n_pages_chunk: %lu\n", n_pages_chunk);

		cur_base = (unsigned long)iov.iov_base & PAGE_MASK;

		while (n_pages_chunk) {
			ret = get_user_pages(
			    current, current->mm, cur_base,
			    min_t(unsigned long, n_pages_chunk,
				  PAGE_SIZE / sizeof(struct page *)),
			    1, !umem->writable, page_list, NULL);
			if (ret < 0) {
				dprint(DBG_ON,
				       "could not get user pages (%d)\n", ret);
				goto fail_get_pages;
			}

			cur_base += ret * PAGE_SIZE;
			n_pages_chunk -= ret;
			off = 0;

			while (ret) {
				int j;

				chunk = kmalloc(
				    sizeof *chunk +
					sizeof(struct scatterlist) *
					    min_t(int, ret,
						  IB_UMEM_MAX_PAGE_CHUNK),
				    GFP_KERNEL);
				if (!chunk) {
					dprint(DBG_ON,
					       "could not alloc chunk\n");
					ret = -ENOMEM;
					goto fail_get_pages;
				}

				chunk->nents =
				    min_t(int, ret, IB_UMEM_MAX_PAGE_CHUNK);
				sg_init_table(chunk->page_list, chunk->nents);
				for (j = 0; j < chunk->nents; j++) {
					sg_set_page(&chunk->page_list[j],
						    page_list[j + off],
						    PAGE_SIZE, 0);
				}

				chunk->nmap = ib_dma_map_sg_attrs(
				    context->device, &chunk->page_list[0],
				    chunk->nents, DMA_BIDIRECTIONAL, &attrs);
				if (chunk->nmap <= 0) {
					for (j = 0; j < chunk->nents; j++)
						put_page(sg_page(
						    &chunk->page_list[j]));
					kfree(chunk);
					ret = -ENOMEM;
					goto fail_get_pages;
				}

				ret -= chunk->nents;
				off += chunk->nents;
				list_add_tail(&chunk->list, &umem->chunk_list);
			}
		}
	}

	current->mm->pinned_vm = locked;

	up_write(&current->mm->mmap_sem);

	gumem->done = true;

	return umem;
fail_get_pages:
	up_write(&current->mm->mmap_sem);
	__ib_umem_release(context->device, umem, 0);
	// fail_page_list:
	free_page((unsigned long)page_list);
fail_umem:
	kfree(umem);
fail:
	return ERR_PTR(ret);
}
