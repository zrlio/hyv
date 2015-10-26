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

#include <hyv.h>

#include "siw_user.h"

#include "virtsiw2_debug.h"

#include "virtsiw2.h"

#define SIW_NODE_DESC "Software iWARP stack"

#define SIW_VENDOR_ID 0

/* TODO: We should really use a loop for this */
static const struct hyv_device_id id_table[] = { { 1, SIW_VENDOR_ID },
						 { 2, SIW_VENDOR_ID },
						 { 3, SIW_VENDOR_ID },
						 { 4, SIW_VENDOR_ID },
						 { 5, SIW_VENDOR_ID },
						 { 6, SIW_VENDOR_ID },
						 { 7, SIW_VENDOR_ID },
						 { 8, SIW_VENDOR_ID },
						 { 9, SIW_VENDOR_ID },
						 { 0 } };

static ssize_t show_sw_version(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%x\n", VERSION_ID_SOFTIWARP_2);
}

static ssize_t show_if_type(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%d\n", 1);
}

static DEVICE_ATTR(sw_version, S_IRUGO, show_sw_version, NULL);
static DEVICE_ATTR(if_type, S_IRUGO, show_if_type, NULL);

static struct device_attribute *virtsiw2_dev_attributes[] = {
	&dev_attr_sw_version, &dev_attr_if_type
};

static void virtsiw2_dma_release(struct device *dev)
{
	/* nothing to do here */
}

static int virtsiw2_probe(struct hyv_device *dev)
{
	struct virtsiw2_device *vdev;
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

	dev_set_name(&vdev->dma_device, "virtsiw2_dma_%d", dev->index);
	vdev->dma_device.release = &virtsiw2_dma_release;

	ret = device_register(&vdev->dma_device);
	if (ret) {
		goto fail_vdev;
	}

	strlcpy(ibdev->name, "vsiw2_%d", IB_DEVICE_NAME_MAX);
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
	    (1ull << IB_USER_VERBS_CMD_DESTROY_QP) |
	    (1ull << IB_USER_VERBS_CMD_REG_MR) |
	    (1ull << IB_USER_VERBS_CMD_DEREG_MR) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
	    (1ull << IB_USER_VERBS_CMD_POST_SEND);
	ibdev->node_type = RDMA_NODE_RNIC;
	strcpy(ibdev->node_desc, SIW_NODE_DESC);
	// TODO: match with host
	ibdev->num_comp_vectors = 1;

	/* dma device */
	ibdev->dma_device = &vdev->dma_device;

	ibdev->alloc_ucontext = &hyv_ibv_alloc_ucontext;
	ibdev->dealloc_ucontext = &hyv_ibv_dealloc_ucontext;

	ibdev->query_device = &hyv_ibv_query_device;
	ibdev->query_port = &hyv_ibv_query_port;
	ibdev->query_pkey = &hyv_ibv_query_pkey;
	ibdev->query_gid = &hyv_ibv_query_gid;

	ibdev->alloc_pd = &hyv_ibv_alloc_pd;
	ibdev->dealloc_pd = &hyv_ibv_dealloc_pd;

	ibdev->create_ah = (void *)0xDEADBEEF;
	ibdev->destroy_ah = (void *)0xDEADBEEF;

	ibdev->create_qp = &virtsiw2_create_qp;
	ibdev->modify_qp = &hyv_ibv_modify_qp;
	ibdev->destroy_qp = &virtsiw2_destroy_qp;

	ibdev->post_send = &virtsiw2_post_send;
	ibdev->post_recv = (void *)0xDEADBEEF;

	ibdev->create_cq = &virtsiw2_create_cq;
	ibdev->destroy_cq = &virtsiw2_destroy_cq;

	ibdev->poll_cq = (void *)0xDEADBEEF;
	ibdev->req_notify_cq = (void *)0xDEADBEEF;

	ibdev->get_dma_mr = (void *)0xDEADBEEF;

	ibdev->reg_user_mr = &hyv_ibv_reg_user_mr;
	ibdev->dereg_mr = &hyv_ibv_dereg_mr;

	ibdev->mmap = &hyv_ibv_mmap;

	/* this is not used -> should be used instead of sw_version */
	ibdev->uverbs_abi_ver = VIRTSIW2_IB_UVERBS_ABI_VERSION;

	ret = ib_register_device(ibdev, NULL);
	if (ret) {
		dprint(DBG_ON, "could not register device!\n");
		goto fail_reg;
	}

	for (i = 0; i < ARRAY_SIZE(virtsiw2_dev_attributes); ++i) {
		ret =
		    device_create_file(&ibdev->dev, virtsiw2_dev_attributes[i]);
		if (ret) {
			dprint(DBG_ON, "device_create_file failed!\n");
			ret = -EFAULT;
			goto fail_reg;
		}
	}

	return 0;
fail_reg:
	device_unregister(&vdev->dma_device);
fail_vdev:
	kfree(vdev);
fail:
	return ret;
}

static int virtsiw2_remove(struct hyv_device *dev)
{
	struct virtsiw2_device *vdev = dev->priv;

	/* detach driver */
	dprint(DBG_DEV, "\n");

	ib_unregister_device(&dev->ibdev);
	dev->priv = NULL;

	device_unregister(&vdev->dma_device);

	kfree(vdev);

	return 0;
}

static struct hyv_driver virtsiw2_driver = { .driver.name = KBUILD_MODNAME,
					     .driver.owner = THIS_MODULE,
					     .id_table = id_table,
					     .probe = virtsiw2_probe,
					     .remove = virtsiw2_remove, };

static int __init init(void)
{
	return register_hyv_driver(&virtsiw2_driver);
}

static void __exit fini(void)
{
	unregister_hyv_driver(&virtsiw2_driver);
}

module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio_hyv, id_table);
MODULE_DESCRIPTION("siw2 virtual provider");
MODULE_LICENSE("GPL");
