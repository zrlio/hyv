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
#include <linux/slab.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>

#include <user.h>

#include <hyv.h>

#include "virtmlx4_debug.h"

#include "virtmlx4.h"

#define MELLANOX 0x2c9

#define CONNECTX3 0x1003
#define CONNECTX3PRO 0x1007

static const struct hyv_device_id id_table[] = { { CONNECTX3, MELLANOX },
						 { CONNECTX3PRO, MELLANOX },
						 { 0 } };

static ssize_t show_vendor(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct virtmlx4_device *vdev =
	    container_of(dev, struct virtmlx4_device, dma_device);
	struct ib_device_attr ibattr;

	if (ib_query_device(&vdev->gdev->ibdev, &ibattr)) {
		dprint(DBG_ON, "query device failed!\n");
		return -EFAULT;
	}

	return sprintf(buf, "0x15b3\n");
}

static ssize_t show_device(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct virtmlx4_device *vdev =
	    container_of(dev, struct virtmlx4_device, dma_device);
	struct ib_device_attr ibattr;

	if (ib_query_device(&vdev->gdev->ibdev, &ibattr)) {
		dprint(DBG_ON, "query device failed!\n");
		return -EFAULT;
	}

	return sprintf(buf, "0x%x\n", ibattr.vendor_part_id);
}

static DEVICE_ATTR(vendor, S_IRUGO, show_vendor, NULL);
static DEVICE_ATTR(device, S_IRUGO, show_device, NULL);

static struct device_attribute *virtmlx4_dma_dev_attributes[] = {
	&dev_attr_vendor, &dev_attr_device
};

enum mlx4_ib_mmap_cmd {
	MLX4_IB_MMAP_UAR_PAGE = 0,
	MLX4_IB_MMAP_BLUE_FLAME_PAGE = 1,
	MLX4_IB_MMAP_GET_CONTIGUOUS_PAGES = 2,
	MLX4_IB_MMAP_GET_HW_CLOCK = 3,
};

static struct ib_ucontext *virtmlx4_alloc_ucontext(struct ib_device *ibdev,
						   struct ib_udata *udata)
{
	struct ib_ucontext *ibuctx;
	struct hyv_ucontext *guctx;
	struct virtmlx4_ucontext *vuctx;
	int ret;

	dprint(DBG_IBV, "\n");

	BUG_ON(!udata);

	ibuctx = hyv_ibv_alloc_ucontext(ibdev, udata);
	if (IS_ERR(ibuctx)) {
		ret = PTR_ERR(ibuctx);
		goto fail;
	}
	guctx = ibuctx_to_hyv(ibuctx);
	guctx->priv = NULL;

	vuctx = kmalloc(sizeof(*vuctx), GFP_KERNEL);
	if (!vuctx) {
		dprint(DBG_ON, "alloc uctx failed\n");
		ret = -ENOMEM;
		goto fail_alloc_uctx;
	}
	guctx->priv = vuctx;

	vuctx->uar_mmap =
	    hyv_mmap_prepare(ibuctx, PAGE_SIZE, MLX4_IB_MMAP_UAR_PAGE);
	if (IS_ERR(vuctx->uar_mmap)) {
		dprint(DBG_ON, "could not prepare uar mmap\n");
		ret = PTR_ERR(vuctx->uar_mmap);
		goto fail_vuctx;
	}

	vuctx->bf_mmap = hyv_mmap_prepare(
	    ibuctx, PAGE_SIZE, MLX4_IB_MMAP_BLUE_FLAME_PAGE << PAGE_SHIFT);
	if (IS_ERR(vuctx->bf_mmap)) {
		dprint(DBG_ON, "could not prepare bf mmap\n");
		ret = PTR_ERR(vuctx->bf_mmap);
		goto fail_uar_mmap;
	}

	return ibuctx;
fail_uar_mmap:
	hyv_mmap_unprepare(ibuctx, vuctx->uar_mmap);
fail_vuctx:
	kfree(vuctx);
fail_alloc_uctx:
	hyv_ibv_dealloc_ucontext(ibuctx);
fail:
	return ERR_PTR(ret);
}

static int virtmlx4_dealloc_ucontext(struct ib_ucontext *ibuctx)
{
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);
	struct virtmlx4_ucontext *vuctx = uctx->priv;

	hyv_unmap(ibuctx, vuctx->uar_mmap);
	hyv_unmap(ibuctx, vuctx->bf_mmap);

	hyv_ibv_dealloc_ucontext(ibuctx);

	kfree(vuctx);

	return 0;
}

static void virtmlx4_dma_release(struct device *dev)
{
	/* nothing to do here */
}

static int virtmlx4_probe(struct hyv_device *dev)
{
	struct virtmlx4_device *vdev;
	struct ib_device *ibdev = &dev->ibdev;
	int ret;
	u32 i;

	/* attach driver */
	dprint(DBG_DEV, "(%llx)\n", dev->ibdev.node_guid);

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev) {
		dprint(DBG_ON, "could not allocate device!\n");
		ret = -ENOMEM;
		goto fail;
	}
	/* we need references in both ways */
	dev->priv = vdev;
	vdev->gdev = dev;

	dev_set_name(&vdev->dma_device, "virtmlx4_dma_%d", dev->index);
	vdev->dma_device.release = &virtmlx4_dma_release;

	ret = device_register(&vdev->dma_device);
	if (ret) {
		goto fail_vdev;
	}

	for (i = 0; i < ARRAY_SIZE(virtmlx4_dma_dev_attributes); ++i) {
		ret = device_create_file(&vdev->dma_device,
					 virtmlx4_dma_dev_attributes[i]);
		if (ret) {
			dprint(DBG_ON, "device_create_file failed!\n");
			ret = -EFAULT;
			goto fail_reg;
		}
	}

	strlcpy(ibdev->name, "vmlx4_%d", IB_DEVICE_NAME_MAX);
	ibdev->owner = THIS_MODULE;
	ibdev->uverbs_cmd_mask =
	    (1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
	    (1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_AH) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_AH) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_QP) |
	    (1ull << IB_USER_VERBS_CMD_MODIFY_QP) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_QP) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_QP) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_SRQ) |
	    (1ull << IB_USER_VERBS_CMD_MODIFY_SRQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_SRQ) |
	    (1ull << IB_USER_VERBS_CMD_REG_MR) |
	    (1ull << IB_USER_VERBS_CMD_DEREG_MR) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL);
	ibdev->node_type = RDMA_NODE_IB_CA;
	strcpy(ibdev->node_desc, "vmlx4 Mellanox");
	// TODO: match with host
	ibdev->num_comp_vectors = 1;

	/* dma device */
	ibdev->dma_device = &vdev->dma_device;

	ibdev->alloc_ucontext = &virtmlx4_alloc_ucontext;
	ibdev->dealloc_ucontext = &virtmlx4_dealloc_ucontext;

	ibdev->query_device = &hyv_ibv_query_device;
	ibdev->query_port = &hyv_ibv_query_port;
	ibdev->query_pkey = &hyv_ibv_query_pkey;
	ibdev->query_gid = &hyv_ibv_query_gid;

	ibdev->alloc_pd = &hyv_ibv_alloc_pd;
	ibdev->dealloc_pd = &hyv_ibv_dealloc_pd;

	ibdev->create_ah = (void *)0xDEADBEEF;
	ibdev->destroy_ah = (void *)0xDEADBEEF;

	ibdev->create_qp = &virtmlx4_create_qp;
	ibdev->modify_qp = &hyv_ibv_modify_qp;
	ibdev->query_qp = &hyv_ibv_query_qp;
	ibdev->destroy_qp = &hyv_ibv_destroy_qp;

	ibdev->create_srq = &virtmlx4_create_srq;
	ibdev->modify_srq = &hyv_ibv_modify_srq;
	ibdev->destroy_srq = &hyv_ibv_destroy_srq;

	ibdev->post_send = (void *)0xDEADBEEF;
	ibdev->post_recv = (void *)0xDEADBEEF;

	ibdev->create_cq = &virtmlx4_create_cq;
	ibdev->destroy_cq = &hyv_ibv_destroy_cq;

	ibdev->poll_cq = (void *)0xDEADBEEF;
	ibdev->req_notify_cq = (void *)0xDEADBEEF;

	ibdev->get_dma_mr = (void *)0xDEADBEEF;

	ibdev->reg_user_mr = &hyv_ibv_reg_user_mr;
	ibdev->dereg_mr = &hyv_ibv_dereg_mr;

	ibdev->mmap = &hyv_ibv_mmap;

	/* we should get the abi from the host */
	ibdev->uverbs_abi_ver = VIRTMLX4_IB_UVERBS_ABI_VERSION;

	ret = ib_register_device(ibdev, NULL);
	if (ret) {
		dprint(DBG_ON, "could not register device!\n");
		goto fail_reg;
	}

	return 0;
fail_reg:
	device_unregister(&vdev->dma_device);
fail_vdev:
	kfree(vdev);
fail:
	return ret;
}

static int virtmlx4_remove(struct hyv_device *dev)
{
	struct virtmlx4_device *vdev = dev->priv;

	/* detach driver */
	dprint(DBG_DEV, "\n");

	ib_unregister_device(&dev->ibdev);
	dev->priv = NULL;

	device_unregister(&vdev->dma_device);

	kfree(vdev);

	return 0;
}

static struct hyv_driver virtmlx4_driver = { .driver.name = KBUILD_MODNAME,
					     .driver.owner = THIS_MODULE,
					     .id_table = id_table,
					     .probe = virtmlx4_probe,
					     .remove = virtmlx4_remove, };

static int __init init(void)
{
	return register_hyv_driver(&virtmlx4_driver);
}

static void __exit fini(void)
{
	unregister_hyv_driver(&virtmlx4_driver);
}

module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio_hyv, id_table);
MODULE_DESCRIPTION("mlx4 virtual provider");
MODULE_LICENSE("GPL v2");
