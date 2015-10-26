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

#ifndef VHOST_HYV_MEM_H_
#define VHOST_HYV_MEM_H_

#include <rdma/ib_verbs.h>
#include <linux/types.h>
#include <linux/mm_types.h>

#include <object_map.h>

#include "vhost_hyv.h"
#include "vhost_hyv_ibv.h"

enum vhost_hyv_mmap_type {
	VHOST_HYV_MMAP_NORMAL,
	VHOST_HYV_MMAP_PFNMAP
};

struct vhost_hyv_mmap
{
	struct object hdr;

	unsigned long hva;
	size_t size;

	enum vhost_hyv_mmap_type type;
	/* remap region starts at this pfn */
	unsigned long pfn;

	/* save to restore */
	struct file *vm_file;
	unsigned long vm_flags;
	unsigned long vm_pgoff;

	struct vhost_hyv_ucontext *uctx;
};

struct vhost_hyv_umem;

int vhost_mem_init(void);
void vhost_mem_exit(void);

void vhost_hyv_mmap_release(struct object *obj);

int vhost_hyv_mmap_wrapper(struct file *f, struct vm_area_struct *vma);

int vhost_hyv_remap(struct vhost_hyv_ucontext *uctx,
		    struct vhost_hyv_mmap *gmmap, uint64_t gpa, size_t size,
		    vm_flags_t vm_flags, unsigned long vm_pgoff,
		    pgprot_t *pgprot);

int vhost_hyv_munmap(struct vhost_hyv_mmap *gmmap);

struct vhost_hyv_umem **
vhost_hyv_ib_umem_prepare(struct vhost_hyv_ucontext *uctx,
			  unsigned long user_va, hyv_user_mem_chunk *gchunk,
			  unsigned long n_chunks);

int vhost_hyv_ib_umem_finish(struct vhost_hyv_umem **umem);
int vhost_hyv_ib_umem_finish_hva(struct vhost_hyv_ucontext *uctx,
				 unsigned long hva);

#endif /* VHOST_HYV_MEM_H_ */
