/*
 * hybrid virtualization (hyv) for linux
 *
 * author: jonas pfefferle <jpf@zurich.ibm.com>
 *
 * copyright (c) 2015, ibm corporation
 *
 * this program is free software; you can redistribute it and/or
 * modify it under the terms of the gnu general public license version 2
 * as published by the free software foundation.
 *
 * this program is distributed in the hope that it will be useful,
 * but without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the
 * gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license
 * along with this program; if not, write to the free software
 * foundation, inc., 51 franklin street, fifth floor, boston, ma  02110-1301,
 *usa.
 */

#include <linux/types.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/kthread.h>
#include <linux/mmzone.h>

#include "vhost_mem.h"

#include "vhost_hyv.h"
#include "vhost_hyv_dev.h"
#include "vhost_hyv_obj.h"
#include "vhost_hyv_debug.h"

#include "vhost_hyv_mem.h"

enum vhost_mem_type {
	VHOST_IO_MEM,
	VHOST_USER_MEM,
	VHOST_USER_MEM_PINNED
};

struct vhost_hyv_mem_chunk_entry
{
	struct vhost_hyv_obj obj;
	u64 n_chunks;
	struct vhost_mem **chunk;
	unsigned long n_pages;
	enum vhost_mem_type mem_type;
	struct page **pages;
	unsigned long user_addr;
};

static int ib_mmap_insert_pfns(struct vhost_hyv *vhyv,
			       struct vhost_hyv_mem_chunk_entry *entry,
			       struct virthyv_cmd_ib_mmap *cmd,
			       struct vm_area_struct *vma)
{
	unsigned long n_pages;
	unsigned long *pfns;
	unsigned long user_addr;
	int ret, i, k;
	int cont = 1;
	int valid = 0;

	n_pages = entry->n_pages;

	pfns = kmalloc(n_pages * sizeof(*pfns), GFP_KERNEL);
	if (!pfns) {
		dprint(DBG_ON, "allocating pfns failed!\n");
		ret = -ENOMEM;
		goto fail;
	}

	user_addr = entry->user_addr;
	for (i = 0; i < n_pages; i++) {
		ret = follow_pfn(vma, user_addr, pfns + i);
		if (ret) {
			dprint(DBG_ON, "follow_pfn failed with %d!\n", ret);
			goto fail_pfns;
		}

		if (pfn_valid(pfns[i])) {
			valid++;
		} else if (i > 0 && pfns[i - 1] + 1 != pfns[i]) {
			cont = 0;
		}

		user_addr += PAGE_SIZE;
	}

	if (valid == 0 && !cont) {
		dprint(DBG_ON, "non consecutive IO memory!\n");
		ret = -EINVAL;
		goto fail_pfns;
	}

	if (valid == n_pages) {
		struct page **pages;

		dprint(DBG_MM, "valid pfns\n");

		pages = kmalloc(n_pages * sizeof(*pages), GFP_KERNEL);
		if (!pages) {
			dprint(DBG_ON, "allocating pages failed!\n");
			ret = -ENOMEM;
			goto fail_pfns;
		}

		for (i = 0; i < n_pages; i++) {
			struct page *page;
			page = pfn_to_page(pfns[i]);
			// XXX: init to 1 if count == 0?
			get_page(page);
			pages[i] = page;
		}

		entry->pages = pages;
		entry->mem_type = VHOST_USER_MEM;

		k = 0;
		for (i = 0; i < cmd->n_chunks; i++) {
			struct vhost_mem *vhost_mem;
			unsigned long chunk_npages;

			chunk_npages = cmd->chunk[i].n_pages;

			dprint(DBG_MM, "chunk has %lu page(s)\n", chunk_npages);

			BUG_ON(k + chunk_npages > n_pages);
			vhost_mem = vhost_remap_pages(
			    &vhyv->dev, cmd->chunk[i].phys, pages + k,
			    chunk_npages, vma->vm_page_prot);
			if (IS_ERR(vhost_mem)) {
				dprint(DBG_ON, "vhost remap pages failed!\n");
				ret = -EFAULT;
				kfree(pages);
				goto fail_remap;
			}

			entry->chunk[i] = vhost_mem;

			k += chunk_npages;
		}

		kfree(pfns);
		return 0;
	}

	if (valid == 0 && cont) {

		dprint(DBG_MM, "IO memory!\n");

		entry->mem_type = VHOST_IO_MEM;

		k = 0;
		for (i = 0; i < cmd->n_chunks; i++) {
			struct vhost_mem *vhost_mem;
			unsigned long chunk_npages;

			chunk_npages = cmd->chunk[i].n_pages;

			dprint(DBG_MM, "chunk has %lu page(s)\n", chunk_npages);

			BUG_ON(k + chunk_npages > n_pages);
			vhost_mem = vhost_io_remap_pfn_range(
			    &vhyv->dev, cmd->chunk[i].phys, pfns[k],
			    chunk_npages, vma->vm_page_prot);
			if (IS_ERR(vhost_mem)) {
				dprint(DBG_ON, "vhost remap pages failed!\n");
				ret = -EFAULT;
				goto fail_remap;
			}

			entry->chunk[i] = vhost_mem;

			k += chunk_npages;
		}

		kfree(pfns);
		return 0;
	} else {
		dprint(DBG_ON, "mixed non-IO/IO pages!\n");
		goto fail_pfns;
	}

fail_remap:
	i--;
	for (; i >= 0; i--) {
		WARN_ON(vhost_restore_mapping(entry->chunk[i]));
	}
fail_pfns:
	kfree(pfns);
fail:
	return ret;
}

static int ib_mmap_insert_pages(struct vhost_hyv *vhyv,
				struct vhost_hyv_mem_chunk_entry *entry,
				struct virthyv_cmd_ib_mmap *cmd,
				struct vm_area_struct *vma)
{
	long pages_pinned;
	struct page **pages;
	struct mm_struct *mm = current->mm;
	int ret, i, k;
	unsigned long n_pages;

	n_pages = entry->n_pages;

	pages = kmalloc(n_pages * sizeof(*pages), GFP_KERNEL);
	if (!pages) {
		dprint(DBG_ON, "allocating pages failed!\n");
		ret = -ENOMEM;
		goto fail;
	}

	down_read(&mm->mmap_sem);
	pages_pinned = get_user_pages(current, mm, entry->user_addr, n_pages, 1,
				      1, pages, NULL);
	up_read(&mm->mmap_sem);
	if (pages_pinned < 0 || (unsigned long)pages_pinned != n_pages) {
		dprint(DBG_ON, "get_user_pages failed with %d",
		       (int)pages_pinned);
		ret = -ENOMEM;
		goto fail_pages;
	}

	entry->pages = pages;
	entry->mem_type = VHOST_USER_MEM_PINNED;

	dprint(DBG_MM, "number of chunks %llu\n", cmd->n_chunks);

	k = 0;
	for (i = 0; i < cmd->n_chunks; i++) {
		struct vhost_mem *vhost_mem;
		unsigned long chunk_npages;

		chunk_npages = cmd->chunk[i].n_pages;

		dprint(DBG_MM, "chunk has %lu page(s)\n", chunk_npages);

		BUG_ON(k + chunk_npages > n_pages);
		vhost_mem =
		    vhost_remap_pages(&vhyv->dev, cmd->chunk[i].phys, pages + k,
				      chunk_npages, vma->vm_page_prot);
		if (IS_ERR(vhost_mem)) {
			dprint(DBG_ON, "vhost remap pages failed!\n");
			ret = -EFAULT;
			goto fail_remap;
		}

		entry->chunk[i] = vhost_mem;

		k += chunk_npages;
	}

	return 0;
fail_remap:
	i--;
	for (; i >= 0; i--) {
		WARN_ON(vhost_restore_mapping(entry->chunk[i]));
	}
fail_pages:
	if (pages_pinned >= 0) {
		for (i = 0; i < min(n_pages, (unsigned long)pages_pinned);
		     i++) {
			put_page(pages[i]);
		}
	}
	kfree(pages);
fail:
	return ret;
}

int vhost_hyv_cmd_ib_mmap(struct vhost_hyv *vhyv,
			  struct virthyv_cmd_ib_mmap __user *ucmd,
			  unsigned long size,
			  struct virthyv_resp_ib_mmap __user *uresp)
{
	struct virthyv_cmd_ib_mmap *cmd;
	struct vm_area_struct *vma;
	struct vhost_hyv_file *file;
	int ret, id, mem_handle;
	unsigned long user_addr;
	unsigned long prot = 0;
	struct vhost_hyv_mem_chunk_entry *entry;
	// should be same as vhyv->dev.mm
	struct mm_struct *mm = current->mm;

	dprint(DBG_MM, "\n");

	if (copy_from_user(&id, &ucmd->handle, sizeof(id))) {
		dprint(DBG_ON, "copy file handle from user failed!\n");
		ret = -EFAULT;
		goto fail;
	}
	file = vhost_hyv_get_file(vhyv, id);
	if (!file) {
		dprint(DBG_ON, "file handle does not exist!\n");
		ret = -EBADF;
		goto fail;
	}

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		dprint(DBG_ON, "allocating entry failed!\n");
		ret = -ENOMEM;
		goto fail;
	}

	cmd = kmalloc(size, GFP_KERNEL);
	if (!cmd) {
		dprint(DBG_ON, "allocating user command failed!\n");
		ret = -ENOMEM;
		goto fail_entry;
	}
	if (copy_from_user(cmd, ucmd, size)) {
		dprint(DBG_ON, "copy_from_user failed!\n");
		ret = -EFAULT;
		goto fail_cmd;
	}

	entry->n_chunks = cmd->n_chunks;

	entry->chunk =
	    kmalloc(entry->n_chunks * sizeof(*entry->chunk), GFP_KERNEL);
	if (!entry->chunk) {
		dprint(DBG_ON, "allocating chunk list failed!\n");
		ret = -ENOMEM;
		goto fail_cmd;
	}

	dprint(DBG_MM,
	       "trying to mmap %llu bytes with key %llu into qemu user space",
	       cmd->size, cmd->key);

	if (pgprot_val(cmd->vm_page_prot) | VM_WRITE) {
		dprint(DBG_MM, "PROT_WRITE\n");
		prot |= PROT_WRITE;
	}
	if (pgprot_val(cmd->vm_page_prot) | VM_READ) {
		dprint(DBG_MM, "PROT_READ\n");
		prot |= PROT_READ;
	}

	// mmap in qemu user space
	// we only need this mapping to get the physical pages, i.e.
	// we could directly unmap. On the other hand unmapping comes
	// with a performance penalty and we better pay that price when we
	// are going to destroy the resource (assuming the address space is
	// large enough)
	user_addr = vm_mmap(file->f, 0, cmd->size, prot, MAP_SHARED, cmd->key);
	if (IS_ERR_VALUE(user_addr)) {
		dprint(DBG_ON, "user mmap failed (%d)!\n", (int)user_addr);
		ret = -ENOMEM;
		goto fail_chunks;
	}

	entry->user_addr = user_addr;

	dprint(DBG_MM, "mmap user address: %lx\n", user_addr);

	vma = find_vma(mm, user_addr);
	if (!vma) {
		dprint(DBG_ON, "find vma failed!\n");
		ret = -EFAULT;
		goto fail_mmap_user;
	}

	entry->n_pages = cmd->size >> PAGE_SHIFT;
	if (vma->vm_flags & (VM_IO | VM_PFNMAP)) {
		ret = ib_mmap_insert_pfns(vhyv, entry, cmd, vma);
		if (ret) {
			dprint(DBG_ON, "insert pfns failed (%d)!\n", ret);
			goto fail_mmap_user;
		}
	} else {
		ret = ib_mmap_insert_pages(vhyv, entry, cmd, vma);
		if (ret) {
			dprint(DBG_ON, "insert pages failed (%d)!\n", ret);
			goto fail_mmap_user;
		}
	}

	mem_handle = vhost_hyv_add_obj(&file->ib_mmappings, &entry->obj);
	if (mem_handle < 0) {
		ret = -EFAULT;
		goto fail_mmap_user;
	}

	if (copy_to_user(&uresp->host_handle, &mem_handle,
			 sizeof(mem_handle))) {
		dprint(DBG_ON, "copy host handle to user failed!\n");
		ret = -EFAULT;
		goto fail_add_obj;
	}

	prot = pgprot_val(vma->vm_page_prot);
	prot &= (_PAGE_CACHE_WC | _PAGE_IOMAP | _PAGE_CACHE_UC_MINUS |
		 _PAGE_CACHE_UC);

	if (copy_to_user(&uresp->extra_pgprot, &prot, sizeof(prot))) {
		dprint(DBG_ON, "copy host handle to user failed!\n");
		ret = -EFAULT;
		goto fail_add_obj;
	}

	kfree(cmd);

	return 0;
fail_add_obj:
	vhost_hyv_remove_obj(&file->ib_mmappings, &entry->obj);
fail_mmap_user:
	vm_munmap(user_addr, cmd->size);
fail_chunks:
	kfree(entry->chunk);
fail_cmd:
	kfree(cmd);
fail_entry:
	kfree(entry);
fail:
	return ret;
}

static void vhost_hyv_ib_unmap_one(struct vhost_hyv_file *file,
				   struct vhost_hyv_mem_chunk_entry *entry,
				   int release)
{
	int i;
	// we only restore the vma if qemu is still running
	if (!release) {
		for (i = 0; i < entry->n_chunks; i++) {
			WARN_ON(vhost_restore_mapping(entry->chunk[i]));
		}
	}
	kfree(entry->chunk);

	switch (entry->mem_type) {
	case VHOST_USER_MEM:
		for (i = 0; i < entry->n_pages; i++) {
			put_page_testzero(entry->pages[i]);
		}
		kfree(entry->pages);
		break;
	case VHOST_USER_MEM_PINNED:
		for (i = 0; i < entry->n_pages; i++) {
			put_page(entry->pages[i]);
		}
		kfree(entry->pages);
		break;
	case VHOST_IO_MEM:
		break;
	}

	if (!release) {
		vm_munmap(entry->user_addr, entry->n_pages * PAGE_SIZE);
	}

	vhost_hyv_remove_obj(&file->ib_mmappings, &entry->obj);
	kfree(entry);
}

struct vhost_hyv_ib_unmap_idr
{
	struct vhost_hyv_file *file;
	int release;
};

static int vhost_hyv_ib_unmap_idr(int id, void *p, void *d)
{
	struct vhost_hyv_ib_unmap_idr *data = d;
	struct vhost_hyv_obj *obj = p;
	struct vhost_hyv_mem_chunk_entry *entry =
	    container_of(obj, struct vhost_hyv_mem_chunk_entry, obj);
	vhost_hyv_ib_unmap_one(data->file, entry, data->release);
	return 0;
}

void vhost_hyv_ib_unmap_all(struct vhost_hyv_file *file, int release)
{
	struct vhost_hyv_ib_unmap_idr data;
	data.file = file;
	data.release = release;
	idr_for_each(&file->ib_mmappings, &vhost_hyv_ib_unmap_idr, &data);
}

int vhost_hyv_cmd_ib_unmap(struct vhost_hyv *vhyv,
			   struct virthyv_cmd_ib_unmap __user *ucmd)
{
	int id, ret = 0;
	struct vhost_hyv_file *file;
	struct vhost_hyv_obj *obj;
	u32 handle;

	dprint(DBG_MM, "\n");

	if (copy_from_user(&id, &ucmd->handle, sizeof(id))) {
		dprint(DBG_ON, "copy file handle from user failed!\n");
		ret = -EFAULT;
		goto out;
	}
	file = vhost_hyv_get_file(vhyv, id);
	if (!file) {
		dprint(DBG_ON, "file handle does not exist!\n");
		ret = -EBADF;
		goto out;
	}

	if (copy_from_user(&handle, &ucmd->mem_handle, sizeof(handle))) {
		dprint(DBG_ON, "copy file handle from user failed!\n");
		ret = -EFAULT;
		goto out;
	}

	obj = vhost_hyv_get_obj(&file->ib_mmappings, handle);
	if (obj) {
		struct vhost_hyv_mem_chunk_entry *entry;
		entry =
		    container_of(obj, struct vhost_hyv_mem_chunk_entry, obj);
		vhost_hyv_ib_unmap_one(file, entry, 0);
	} else {
		dprint(DBG_ON, "invalid handle!\n");
		ret = -EINVAL;
	}
out:
	return ret;
}

struct vhost_hyv_mmap_entry
{
	struct vhost_hyv_obj obj;
	unsigned long user_addr;
	unsigned long size;
};

int vhost_hyv_cmd_mmap(struct vhost_hyv *vhyv,
		       struct virthyv_cmd_mmap __user *ucmd, unsigned long size,
		       struct virthyv_resp_mmap __user *uresp)
{
	struct virthyv_cmd_mmap *cmd;
	struct vhost_hyv_mmap_entry *entry;
	unsigned long i;
	u64 va;
	int ret, handle;
	struct vhost_mem_region *regions;

	cmd = kmalloc(size, GFP_KERNEL);
	if (!cmd) {
		dprint(DBG_ON, "allocating user command failed!\n");
		ret = -ENOMEM;
		goto fail;
	}

	if (copy_from_user(cmd, ucmd, size)) {
		dprint(DBG_ON, "copy_from_user failed!\n");
		ret = -EFAULT;
		goto fail_cmd;
	}

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		dprint(DBG_ON, "allocating entry failed!\n");
		ret = -ENOMEM;
		goto fail_cmd;
	}

	dprint(DBG_MM, "n_chunks: %llu\n", cmd->n_chunks);

	regions = kmalloc(sizeof(*regions) * cmd->n_chunks, GFP_KERNEL);
	if (!regions) {
		dprint(DBG_ON, "allocating user command failed!\n");
		ret = -ENOMEM;
		goto fail_entry;
	}

	entry->size = 0;
	for (i = 0; i < cmd->n_chunks; i++) {
		regions[i].gpa = cmd->chunk[i].phys;
		regions[i].size = cmd->chunk[i].n_pages * PAGE_SIZE;
		entry->size += regions[i].size;
	}

	va = vhost_mmap_cont(&vhyv->dev, regions, cmd->n_chunks);
	if (IS_ERR_VALUE(va)) {
		dprint(DBG_ON, "mmap cont failed!\n");
		ret = (int)va;
		goto fail_regions;
	}

	entry->user_addr = va;

	handle = vhost_hyv_add_obj(&vhyv->mmappings, &entry->obj);
	if (handle < 0) {
		ret = -EFAULT;
		goto fail_mmap;
	}

	if (copy_to_user(&uresp->host_va, &va, sizeof(va))) {
		dprint(DBG_ON, "copy va to response failed\n");
		goto fail_mmap;
	}

	if (copy_to_user(&uresp->host_handle, &handle, sizeof(handle))) {
		dprint(DBG_ON, "copy host handle to response failed\n");
		goto fail_mmap;
	}

	kfree(regions);
	kfree(cmd);

	return 0;
fail_mmap:
	vhost_unmap_cont(va, entry->size);
fail_regions:
	kfree(regions);
fail_entry:
	kfree(entry);
fail_cmd:
	kfree(cmd);
fail:
	return ret;
}

int vhost_hyv_cmd_unmap(struct vhost_hyv *vhyv,
			struct virthyv_cmd_unmap __user *ucmd)
{
	struct virthyv_cmd_unmap cmd;
	struct vhost_hyv_obj *obj;
	int ret = 0;

	dprint(DBG_MM, "\n");

	if (copy_from_user(&cmd, ucmd, sizeof(cmd))) {
		dprint(DBG_ON, "copy_from_user failed!\n");
		ret = -EFAULT;
		goto out;
	}

	obj = vhost_hyv_get_obj(&vhyv->mmappings, cmd.mem_handle);
	if (obj) {
		struct vhost_hyv_mmap_entry *entry;
		entry = container_of(obj, struct vhost_hyv_mmap_entry, obj);
		WARN_ON(vhost_unmap_cont(entry->user_addr, entry->size));
		vhost_hyv_remove_obj(&vhyv->mmappings, obj);
	} else {
		dprint(DBG_ON, "invalid handle\n");
		ret = -EINVAL;
	}
out:
	return ret;
}
