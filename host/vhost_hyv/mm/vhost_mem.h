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

#ifndef VHOST_MEM_H_
#define VHOST_MEM_H_

#include <linux/types.h>

struct vhost_mem;
struct vhost_dev;
struct page;

struct vhost_mem_region
{
	u64 gpa;
	unsigned long size;
};

void vhost_mem_init(void);

struct vhost_mem *vhost_io_remap_pfn_range(struct vhost_dev *dev, u64 gpa,
					   unsigned long pfn,
					   unsigned long n_pages,
					   pgprot_t page_prot);

struct vhost_mem *vhost_remap_pages(struct vhost_dev *dev, u64 gpa,
				    struct page **pages, unsigned long n_pages,
				    pgprot_t page_prot);

int vhost_restore_mapping(struct vhost_mem *mem);

unsigned long vhost_mmap_cont(struct vhost_dev *dev,
			      struct vhost_mem_region *regions,
			      unsigned long n_regions);

int vhost_unmap_cont(unsigned long va, unsigned long size);

#endif /* VHOST_MEM_H_ */
