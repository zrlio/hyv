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
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/kthread.h>
#include <linux/vhost.h>
// XXX: weired dependecy!
#include <linux/virtio_net.h>
#include <linux/kallsyms.h>

#include <linux/mempolicy.h>

#include "vhost.h"

// TODO: remove
#include "vhost_hyv_debug.h"

#include "vhost_mem.h"

struct vhost_mem
{
	unsigned long hva;
	struct file *file;
	unsigned long pgoff;
	unsigned long size;
	unsigned long flags;
};

static int (*_do_munmap)(struct mm_struct *, unsigned long, size_t);
static unsigned long (*_do_mmap_pgoff)(struct file *, unsigned long,
				       unsigned long, unsigned long,
				       unsigned long, unsigned long,
				       unsigned long *);
static unsigned long (*_mmap_region)(struct file *, unsigned long,
				     unsigned long, vm_flags_t, unsigned long);

void vhost_mem_init(void)
{
	_do_munmap = (void *)kallsyms_lookup_name("do_munmap");
	if (!_do_munmap) {
		dprint(DBG_ON, "Could not find symbol do_munmap!\n");
		BUG();
	}
	_do_mmap_pgoff = (void *)kallsyms_lookup_name("do_mmap_pgoff");
	if (!_do_mmap_pgoff) {
		dprint(DBG_ON, "Could not find symbol do_mmap_pgoff!\n");
		BUG();
	}
	_mmap_region = (void *)kallsyms_lookup_name("mmap_region");
	if (!_mmap_region) {
		dprint(DBG_ON, "Could not find symbol mmap_region!\n");
		BUG();
	}
}

struct vhost_mem *vhost_io_remap_pfn_range(struct vhost_dev *dev, u64 gpa,
					   unsigned long pfn,
					   unsigned long n_pages,
					   pgprot_t page_prot)
{
	unsigned long size;
	int ret, i;
	struct iovec iov;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct file *file;
	struct address_space *mapping;
	unsigned long pgoff;
	unsigned long hva;
	unsigned long remapped_hva;
	unsigned long prot = 0;
	unsigned long flags;
	unsigned long populate;
	struct vhost_mem *mem;

	if (n_pages == 0) {
		dprint(DBG_ON, "remap 0 pages?\n");
		ret = 0;
		goto fail;
	}

	for (i = 0; i < n_pages; i++) {
		if (pfn_valid(pfn + i)) {
			dprint(DBG_ON, "Not an IO page!\n");
			ret = -EINVAL;
			goto fail;
		}
	}

	size = n_pages * PAGE_SIZE;
	ret = vhost_gpm_to_hvm(dev, gpa, size, &iov, 1);
	if (ret != 1) {
		dprint(DBG_ON, "translating gpm to hvm failed!\n");
		ret = ret < 0 ? ret : -EFAULT;
		goto fail;
	}
	hva = (unsigned long)iov.iov_base;
	hva = hva & PAGE_MASK;
	if (iov.iov_len < size) {
		dprint(DBG_ON, "size mismatch of memory region!\n");
		ret = -EFAULT;
		goto fail;
	}

	dprint(DBG_MM, "Translate gpa 0x%llx to hva %lx\n", gpa, hva);

	down_write(&mm->mmap_sem);

	vma = find_vma(mm, hva);
	if (!vma) {
		dprint(DBG_ON, "find_vma failed!\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	if (vma->vm_flags & (VM_IO | VM_PFNMAP)) {
		dprint(DBG_ON, "already remapped!\n");
		ret = -EINVAL;
		goto fail_mmap_sem;
	}

	if (hva < vma->vm_start || hva + size > vma->vm_end) {
		struct vm_area_struct *prev_vma;
		struct mempolicy *a, *b;
		a = vma->vm_policy;
		dprint(DBG_ON, "not in vma [0x%lx, 0x%lx]: %lx (%lx)!\n",
		       vma->vm_start, vma->vm_end, hva, size);
		prev_vma = find_vma(mm, vma->vm_start - 1);

		dprint(DBG_ON, "end == start: %d\n",
		       prev_vma->vm_end == vma->vm_start);
		b = prev_vma->vm_policy;
		dprint(DBG_ON, "policy: %d\n", a == b);
		if (a && b) {
			switch (a->mode) {
			case MPOL_BIND:
			case MPOL_INTERLEAVE:
				dprint(DBG_ON, "node equal: %d\n",
				       !!nodes_equal(a->v.nodes, b->v.nodes));
				break;
			case MPOL_PREFERRED:
				dprint(DBG_ON, "prefered: %d\n",
				       a->v.preferred_node ==
					   b->v.preferred_node);
				break;
			}
		}
		dprint(DBG_ON, "flags: %lu\n",
		       vma->vm_flags ^ prev_vma->vm_flags);
		dprint(DBG_ON, "vma->vm_flags: %lx\n", vma->vm_flags);
		dprint(DBG_ON, "prev_vma->vm_flags: %lx\n", prev_vma->vm_flags);
		dprint(DBG_ON, "has close: %d\n",
		       vma->vm_ops && vma->vm_ops->close);
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	file = vma->vm_file;
	if (!file) {
		dprint(DBG_ON, "not backed by file?\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	mapping = file->f_mapping;
	if (!mapping) {
		dprint(DBG_ON, "mapping null?\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	flags = vma->vm_flags;
	pgoff = ((hva - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;

	ret = _do_munmap(mm, hva, size);
	if (ret) {
		dprint(DBG_ON, "unmap failed!\n");
		goto fail_mmap_sem;
	}

	if (pgprot_val(vma->vm_page_prot) | VM_WRITE) {
		dprint(DBG_MM, "PROT_WRITE\n");
		prot |= PROT_WRITE;
	}
	if (pgprot_val(vma->vm_page_prot) | VM_READ) {
		dprint(DBG_MM, "PROT_READ\n");
		prot |= PROT_READ;
	}

	remapped_hva = _do_mmap_pgoff(NULL, hva, size, prot,
				      MAP_SHARED | MAP_FIXED, 0, &populate);
	if (hva != remapped_hva) {
		dprint(DBG_ON, "mmap failed!\n");
		goto fail_unmap;
	}

	vma = find_vma(mm, hva);
	if (!vma) {
		dprint(DBG_ON, "find_vma (2) failed!\n");
		ret = -EFAULT;
		goto fail_mmap;
	}

	// kvm uses the page offset to get the pfn:
	// (addr - vm_start) >> PAGE_SHIFT + pgoff
	vma->vm_pgoff = pfn;
	vma->vm_page_prot = page_prot;

	dprint(DBG_MM, "insert pfns at %05lx\n", pfn);
	ret = remap_pfn_range(vma, hva, pfn, n_pages * PAGE_SIZE,
			      vma->vm_page_prot);
	if (ret) {
		dprint(DBG_ON, "remap pfn range failed (%d)!\n", ret);
		goto fail_mmap;
	}

	up_write(&mm->mmap_sem);

	mem = kmalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem) {
		dprint(DBG_ON, "allocating vhost mem failed!\n");
		ret = -ENOMEM;
		goto fail_mmap;
	}

	mem->file = file;
	mem->hva = hva;
	mem->pgoff = pgoff;
	mem->size = size;
	mem->flags = flags;

	return mem;
fail_mmap:
	ret = _do_munmap(mm, hva, size);
	if (ret) {
		dprint(DBG_ON, "unmap (2) failed!\n");
	}
fail_unmap:
	remapped_hva = _mmap_region(file, hva, size, flags, pgoff);
	if (hva != remapped_hva) {
		dprint(DBG_ON, "restore mapping failed!\n");
	}
fail_mmap_sem:
	up_write(&mm->mmap_sem);
fail:
	return ERR_PTR(ret);
}

// TODO: merge this function with vhost_io_remap
struct vhost_mem *vhost_remap_pages(struct vhost_dev *dev, u64 gpa,
				    struct page **pages, unsigned long n_pages,
				    pgprot_t page_prot)
{
	unsigned long size;
	int ret;
	struct iovec iov;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct file *file;
	struct address_space *mapping;
	unsigned long pgoff;
	unsigned long hva, va;
	unsigned long remapped_hva;
	unsigned long i;
	unsigned long prot = 0;
	unsigned long flags;
	unsigned long populate;
	struct vhost_mem *mem;

	size = n_pages * PAGE_SIZE;
	ret = vhost_gpm_to_hvm(dev, gpa, size, &iov, 1);
	if (ret != 1) {
		// we are pretty sure that the chunk does not span over
		// several memory regions as it is ram mem in the guest
		dprint(DBG_ON, "translating gpm to hvm failed!\n");
		ret = ret < 0 ? ret : -EFAULT;
		goto fail;
	}
	hva = (unsigned long)iov.iov_base;
	hva = hva & PAGE_MASK;
	if (iov.iov_len < size) {
		dprint(DBG_ON, "size mismatch of memory region!\n");
		ret = -EFAULT;
		goto fail;
	}

	dprint(DBG_MM, "Translate gpa 0x%llx to hva %lx\n", gpa, hva);

	down_write(&mm->mmap_sem);

	vma = find_vma(mm, hva);
	if (!vma) {
		dprint(DBG_ON, "find_vma failed!\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	if (hva < vma->vm_start || hva + size > vma->vm_end) {
		dprint(DBG_ON, "not in vma!\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	file = vma->vm_file;
	if (!file) {
		dprint(DBG_ON, "not backed by file?\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	mapping = file->f_mapping;
	if (!mapping) {
		dprint(DBG_ON, "mapping null?\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	flags = vma->vm_flags;
	pgoff = ((hva - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;

	ret = _do_munmap(mm, hva, size);
	if (ret) {
		dprint(DBG_ON, "unmap failed!\n");
		goto fail_mmap_sem;
	}

	if (pgprot_val(vma->vm_page_prot) | VM_WRITE) {
		dprint(DBG_MM, "PROT_WRITE\n");
		prot |= PROT_WRITE;
	}
	if (pgprot_val(vma->vm_page_prot) | VM_READ) {
		dprint(DBG_MM, "PROT_READ\n");
		prot |= PROT_READ;
	}

	remapped_hva = _do_mmap_pgoff(NULL, hva, size, prot,
				      MAP_SHARED | MAP_FIXED, 0, &populate);
	if (hva != remapped_hva) {
		dprint(DBG_ON, "mmap failed!\n");
		goto fail_unmap;
	}

	vma = find_vma(mm, hva);
	if (!vma) {
		dprint(DBG_ON, "find_vma (2) failed!\n");
		ret = -EFAULT;
		goto fail_mmap;
	}

	vma->vm_page_prot = page_prot;

	va = hva;
	for (i = 0; i < n_pages; i++) {
		ret = vm_insert_page(vma, va, pages[i]);
		if (ret) {
			dprint(DBG_ON, "vm_insert_page failed (%d)!\n", ret);
			goto fail_unmap;
		}
		va += PAGE_SIZE;
	}

	up_write(&mm->mmap_sem);

	mem = kmalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem) {
		dprint(DBG_ON, "allocating vhost mem failed!\n");
		ret = -ENOMEM;
		goto fail_unmap;
	}

	mem->file = file;
	mem->hva = hva;
	mem->size = size;
	mem->pgoff = pgoff;
	mem->flags = flags;

	return mem;
fail_mmap:
	ret = _do_munmap(mm, hva, size);
	if (ret) {
		dprint(DBG_ON, "unmap (2) failed!\n");
	}
fail_unmap:
	remapped_hva = _mmap_region(file, hva, size, flags, pgoff);
	if (hva != remapped_hva) {
		dprint(DBG_ON, "restore mapping failed!\n");
	}
fail_mmap_sem:
	up_write(&mm->mmap_sem);
fail:
	return ERR_PTR(ret);
}

int vhost_restore_mapping(struct vhost_mem *mem)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int ret = 0;
	unsigned long remapped_hva;

	down_write(&mm->mmap_sem);

	vma = find_vma(mm, mem->hva);
	if (!vma) {
		dprint(DBG_ON, "find_vma failed!\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	if (mem->hva < vma->vm_start || mem->hva + mem->size > vma->vm_end) {
		dprint(DBG_ON, "not in vma!\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	if (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP)) {
		ret = _do_munmap(mm, mem->hva, mem->size);
		if (ret) {
			dprint(DBG_ON, "unmap failed!\n");
			goto fail_mmap_sem;
		}

		remapped_hva = _mmap_region(mem->file, mem->hva, mem->size,
					    mem->flags, mem->pgoff);
		if (mem->hva != remapped_hva) {
			dprint(DBG_ON, "mmap_region failed!\n");
			ret = -EFAULT;
			goto fail_mmap_sem;
		}
	} else {
		dprint(DBG_ON,
		       "Try to restore mapping that was never remapped!\n");
	}

fail_mmap_sem:
	up_write(&mm->mmap_sem);
	kfree(mem);
	return ret;
}

unsigned long vhost_mmap_cont(struct vhost_dev *dev,
			      struct vhost_mem_region *regions,
			      unsigned long n_regions)
{
	int ret;
	unsigned long va;
	struct iovec iov;
	struct mm_struct *mm = current->mm;
	unsigned long size = 0;

	if (n_regions == 0) {
		ret = -EINVAL;
		goto fail;
	}

	ret =
	    vhost_gpm_to_hvm(dev, regions[0].gpa, regions[0].size, &iov, 1);
	if (ret != 1) {
		// we are pretty sure that the chunk does not span over
		// several memory regions as it is ram mem in the guest
		dprint(DBG_ON, "translating gpm to hvm failed!\n");
		ret = -EFAULT;
		goto fail;
	}

	va = (unsigned long)iov.iov_base;

	// we only need to translate from gpa to hvm if we have only one
	// contiguous chunk of phys memory
	if (n_regions > 1) {
		struct vm_area_struct *vma;
		unsigned long i;
		vm_flags_t vm_flags;
		unsigned long user_addr;
		unsigned long start;

		dprint(DBG_MM, "More than one chunk thus we create a nonlinear "
			       "mapping into qemu user space\n");

		down_write(&mm->mmap_sem);

		vma = find_vma(mm, va);
		if (!vma) {
			dprint(DBG_ON, "find_vma failed!\n");
			ret = -EFAULT;
			goto fail_mmap_sem;
		}

		if (vma->vm_flags & (VM_IO | VM_PFNMAP)) {
			dprint(DBG_ON, "cannot contiguously map remapped"
				       "memory!\n");
			ret = -EINVAL;
			goto fail_mmap_sem;
		}

		if (!vma->vm_file) {
			dprint(DBG_ON, "not backed by file?\n");
			ret = -EFAULT;
			goto fail_mmap_sem;
		}
		start = vma->vm_start - (vma->vm_pgoff * PAGE_SIZE);

		for (i = 0; i < n_regions; i++) {
			size += regions[i].size;
		}

		va = get_unmapped_area(vma->vm_file, 0, size, 0, MAP_SHARED);
		if (va & ~PAGE_MASK) {
			dprint(DBG_ON, "get unmapped area failed!\n");
			ret = -EFAULT;
			goto fail_mmap_sem;
		}

		vm_flags = calc_vm_prot_bits(PROT_READ | PROT_WRITE);
		vm_flags |= mm->def_flags;
		vm_flags |= VM_MAYREAD | VM_MAYWRITE;
		vm_flags |= VM_SHARED | VM_MAYSHARE;
		vm_flags |= VM_NONLINEAR;

		va = _mmap_region(vma->vm_file, va, size, vm_flags, 0);
		if (IS_ERR_VALUE(va)) {
			ret = (int)va;
			dprint(DBG_ON, "_mmap_region failed (%d)!\n", ret);
			goto fail_mmap_sem;
		}

		vma = find_vma(mm, va);
		if (!vma) {
			dprint(DBG_ON, "find_vma (2) failed!\n");
			ret = -EFAULT;
			goto fail_mmap_region;
		}

		if (!vma->vm_ops || !vma->vm_ops->remap_pages) {
			dprint(DBG_ON, "no remap pages op!\n");
			ret = -EFAULT;
			goto fail_mmap_region;
		}

		user_addr = va;
		for (i = 0; i < n_regions; i++) {
			unsigned long pgoff;

			ret = vhost_gpm_to_hvm(dev, regions[i].gpa,
						   regions[i].size, &iov, 1);
			if (ret != 1) {
				dprint(DBG_ON,
				       "translating gpm to hvm failed!\n");
				ret = -EFAULT;
				goto fail_mmap_region;
			}
			pgoff =
			    ((unsigned long)iov.iov_base - start) >> PAGE_SHIFT;
			dprint(DBG_MM, "pgoff: %lu\n", pgoff);

			ret = vma->vm_ops->remap_pages(vma, user_addr,
						       regions[i].size, pgoff);
			if (ret) {
				dprint(DBG_ON, "remap pages failed (%d)!\n",
				       ret);
				goto fail_mmap_region;
			}
			user_addr += regions[i].size;
		}

		up_write(&mm->mmap_sem);
	}

	return va;
fail_mmap_region:
	WARN_ON(_do_munmap(mm, va, size));
fail_mmap_sem:
	up_write(&mm->mmap_sem);
fail:
	return ret;
}

int vhost_unmap_cont(unsigned long va, unsigned long size)
{
	struct vm_area_struct *vma;
	int ret = 0;
	struct mm_struct *mm = current->mm;

	down_write(&mm->mmap_sem);

	vma = find_vma(mm, va);
	if (!vma) {
		dprint(DBG_ON, "find_vma failed!\n");
		ret = -EFAULT;
		goto fail_mmap_sem;
	}

	if (vma->vm_flags & VM_NONLINEAR) {
		ret = _do_munmap(mm, va, size);
		if (ret) {
			dprint(DBG_ON, "unmap failed (%d)!\n", ret);
			goto fail_mmap_sem;
		}
	}
// else: if vma is not nonlinear we did not create a new mapping
// and thus there is nothing to do here

fail_mmap_sem:
	up_write(&mm->mmap_sem);
	return ret;
}
