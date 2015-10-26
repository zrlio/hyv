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

#ifndef HYV_MEM_H_
#define HYV_MEM_H_

struct hyv_user_mem;

struct hyv_mmap *hyv_mmap_get(struct ib_ucontext *ibuctx, uint32_t key);

struct hyv_user_mem *hyv_pin_user_mem(unsigned long va, unsigned long size,
				      hyv_user_mem_chunk **chunks,
				      unsigned long *n_chunks, bool write);

void hyv_unpin_user_mem(struct hyv_user_mem *umem);

#endif /* HYV_MEM_H_ */
