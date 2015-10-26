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

#include <linux/version.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <rdma/ib_verbs.h>

#include "virtc4iw_dma.h"

/*
 * DMA mapping/address translation functions.
 * Used to populate virtc4iw private DMA mapping functions of
 * struct ib_dma_mapping_ops in struct ib_dev - see rdma/ib_verbs.h
 */

static int virtc4iw_mapping_error(struct ib_device *dev, u64 dma_addr)
{
	return dma_addr == 0;
}

static u64 virtc4iw_dma_map_single(struct ib_device *dev, void *kva,
				   size_t size, enum dma_data_direction dir)
{
	return virt_to_phys(kva);
}

static void virtc4iw_dma_unmap_single(struct ib_device *dev, u64 addr,
				      size_t size, enum dma_data_direction dir)
{
	/* NOP */
}

static u64 virtc4iw_dma_map_page(struct ib_device *dev, struct page *page,
				 unsigned long offset, size_t size,
				 enum dma_data_direction dir)
{
	BUG_ON(!valid_dma_direction(dir));

	return page_to_phys(page) + offset;
}

static void virtc4iw_dma_unmap_page(struct ib_device *dev, u64 addr,
				    size_t size, enum dma_data_direction dir)
{
	/* NOP */
}

static int virtc4iw_dma_map_sg(struct ib_device *dev, struct scatterlist *sgl,
			       int n_sge, enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	BUG_ON(!valid_dma_direction(dir));

	for_each_sg(sgl, sg, n_sge, i)
	{
		sg->dma_address = page_to_phys(sg_page(sg));
		sg_dma_len(sg) = sg->length;
	}
	return n_sge;
}

static void virtc4iw_dma_unmap_sg(struct ib_device *dev,
				  struct scatterlist *sgl, int n_sge,
				  enum dma_data_direction dir)
{
	/* NOP */
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
static u64 virtc4iw_dma_address(struct ib_device *dev, struct scatterlist *sg)
{
	return page_to_phys(sg_page(sg));
}

static unsigned int virtc4iw_dma_len(struct ib_device *dev,
				     struct scatterlist *sg)
{
	return sg_dma_len(sg);
}
#endif

static void virtc4iw_sync_single_for_cpu(struct ib_device *dev, u64 addr,
					 size_t size,
					 enum dma_data_direction dir)
{
	/* NOP */
}

static void virtc4iw_sync_single_for_device(struct ib_device *dev, u64 addr,
					    size_t size,
					    enum dma_data_direction dir)
{
	/* NOP */
}

static void *virtc4iw_dma_alloc_coherent(struct ib_device *dev, size_t size,
					 u64 *dma_addr, gfp_t flag)
{
	struct page *page;
	void *kva = NULL;

	page = alloc_pages(flag, get_order(size));
	if (page) {
		kva = page_address(page);
		if (dma_addr) {
			*dma_addr = page_to_phys(page);
		}
	}

	return kva;
}

static void virtc4iw_dma_free_coherent(struct ib_device *dev, size_t size,
				       void *kva, u64 dma_addr)
{
	free_pages((unsigned long)kva, get_order(size));
}

struct ib_dma_mapping_ops virtc4iw_dma_mapping_ops = {
	.mapping_error = virtc4iw_mapping_error,
	.map_single = virtc4iw_dma_map_single,
	.unmap_single = virtc4iw_dma_unmap_single,
	.map_page = virtc4iw_dma_map_page,
	.unmap_page = virtc4iw_dma_unmap_page,
	.map_sg = virtc4iw_dma_map_sg,
	.unmap_sg = virtc4iw_dma_unmap_sg,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	.dma_address = virtc4iw_dma_address,
	.dma_len = virtc4iw_dma_len,
#endif
	.sync_single_for_cpu = virtc4iw_sync_single_for_cpu,
	.sync_single_for_device = virtc4iw_sync_single_for_device,
	.alloc_coherent = virtc4iw_dma_alloc_coherent,
	.free_coherent = virtc4iw_dma_free_coherent
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
static void *virtc4iw_dma_generic_alloc_coherent(struct device *dev,
						 size_t size,
						 dma_addr_t *dma_handle,
						 gfp_t gfp)
{
	return virtc4iw_dma_alloc_coherent(NULL, size, dma_handle, gfp);
}

static void virtc4iw_dma_generic_free_coherent(struct device *dev, size_t size,
					       void *vaddr,
					       dma_addr_t dma_handle)
{
	virtc4iw_dma_free_coherent(NULL, size, vaddr, dma_handle);
}
#else
static void *virtc4iw_dma_generic_alloc(struct device *dev, size_t size,
					dma_addr_t *dma_handle, gfp_t gfp,
					struct dma_attrs *attrs)
{
	return virtc4iw_dma_alloc_coherent(NULL, size, dma_handle, gfp);
}

static void virtc4iw_dma_generic_free(struct device *dev, size_t size,
				      void *vaddr, dma_addr_t dma_handle,
				      struct dma_attrs *attrs)
{
	virtc4iw_dma_free_coherent(NULL, size, vaddr, dma_handle);
}
#endif

static dma_addr_t virtc4iw_dma_generic_map_page(
    struct device *dev, struct page *page, unsigned long offset, size_t size,
    enum dma_data_direction dir, struct dma_attrs *attrs)
{
	return virtc4iw_dma_map_page(NULL, page, offset, size, dir);
}

static void virtc4iw_dma_generic_unmap_page(struct device *dev,
					    dma_addr_t handle, size_t size,
					    enum dma_data_direction dir,
					    struct dma_attrs *attrs)
{
	virtc4iw_dma_unmap_page(NULL, handle, size, dir);
}

static int virtc4iw_dma_generic_map_sg(struct device *dev,
				       struct scatterlist *sg, int nents,
				       enum dma_data_direction dir,
				       struct dma_attrs *attrs)
{
	return virtc4iw_dma_map_sg(NULL, sg, nents, dir);
}

static void virtc4iw_dma_generic_unmap_sg(struct device *dev,
					  struct scatterlist *sg, int nents,
					  enum dma_data_direction dir,
					  struct dma_attrs *attrs)
{
	virtc4iw_dma_unmap_sg(NULL, sg, nents, dir);
}

static void virtc4iw_generic_sync_single_for_cpu(struct device *dev,
						 dma_addr_t dma_handle,
						 size_t size,
						 enum dma_data_direction dir)
{
	virtc4iw_sync_single_for_cpu(NULL, dma_handle, size, dir);
}

static void virtc4iw_generic_sync_single_for_device(struct device *dev,
						    dma_addr_t dma_handle,
						    size_t size,
						    enum dma_data_direction dir)
{
	virtc4iw_sync_single_for_device(NULL, dma_handle, size, dir);
}

static void virtc4iw_generic_sync_sg_for_cpu(struct device *dev,
					     struct scatterlist *sg, int nents,
					     enum dma_data_direction dir)
{
	/* NOP */
}

static void virtc4iw_generic_sync_sg_for_device(struct device *dev,
						struct scatterlist *sg,
						int nents,
						enum dma_data_direction dir)
{
	/* NOP */
}

static int virtc4iw_dma_generic_mapping_error(struct device *dev,
					      dma_addr_t dma_addr)
{
	return virtc4iw_mapping_error(NULL, dma_addr);
}

static int virtc4iw_dma_generic_supported(struct device *dev, u64 mask)
{
	return 1;
}

static int virtc4iw_dma_generic_set_mask(struct device *dev, u64 mask)
{
	if (!dev->dma_mask || !dma_supported(dev, mask))
		return -EIO;

	*dev->dma_mask = mask;

	return 0;
}

struct dma_map_ops virtc4iw_dma_generic_ops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
	.alloc_coherent = virtc4iw_dma_generic_alloc_coherent,
	.free_coherent = virtc4iw_dma_generic_free_coherent,
#else
	.alloc = virtc4iw_dma_generic_alloc,
	.free = virtc4iw_dma_generic_free,
#endif
	.map_page = virtc4iw_dma_generic_map_page,
	.unmap_page = virtc4iw_dma_generic_unmap_page,
	.map_sg = virtc4iw_dma_generic_map_sg,
	.unmap_sg = virtc4iw_dma_generic_unmap_sg,
	.sync_single_for_cpu = virtc4iw_generic_sync_single_for_cpu,
	.sync_single_for_device = virtc4iw_generic_sync_single_for_device,
	.sync_sg_for_cpu = virtc4iw_generic_sync_sg_for_cpu,
	.sync_sg_for_device = virtc4iw_generic_sync_sg_for_device,
	.mapping_error = virtc4iw_dma_generic_mapping_error,
	.dma_supported = virtc4iw_dma_generic_supported,
	.set_dma_mask = virtc4iw_dma_generic_set_mask,
	.is_phys = 1
};
