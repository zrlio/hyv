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

#include "virtc4iw_debug.h"

#include <t4fw_interface.h>
#include <user.h>

#include "virtc4iw_dma.h"
#include "virtc4iw.h"

#define CHELSIO 0x1425

#define T420CR 0x4401
#define T580CR 0x540d

static const struct hyv_device_id id_table[] = { { T420CR, CHELSIO },
						 { T580CR, CHELSIO }, { 0 } };

static void virtc4iw_dma_release(struct device *dev)
{
	/* nothing to do here */
}

static int virtc4iw_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
			       u16 *pkey)
{
	dprint(DBG_IBV, "\n");
	*pkey = 0;
	return 0;
}

static ssize_t show_fw_ver(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct ib_device *ibdev = container_of(dev, struct ib_device, dev);
	struct ib_device_attr ibattr;

	dprint(DBG_ATTR, "\n");

	if (ib_query_device(ibdev, &ibattr)) {
		dprint(DBG_ON, "query device failed!\n");
		return -EFAULT;
	}

	return sprintf(buf, "%llu.%llu.%llu.%llu\n",
		       G_FW_HDR_FW_VER_MAJOR(ibattr.fw_ver),
		       G_FW_HDR_FW_VER_MINOR(ibattr.fw_ver),
		       G_FW_HDR_FW_VER_MICRO(ibattr.fw_ver),
		       G_FW_HDR_FW_VER_BUILD(ibattr.fw_ver));
}

static DEVICE_ATTR(fw_ver, S_IRUGO, show_fw_ver, NULL);

static struct device_attribute *virtc4iw_class_attributes[] = {
	&dev_attr_fw_ver
};

static ssize_t show_vendor(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct virtc4iw_device *vdev =
	    container_of(dev, struct virtc4iw_device, dma_device);
	struct ib_device_attr ibattr;

	if (ib_query_device(&vdev->gdev->ibdev, &ibattr)) {
		dprint(DBG_ON, "query device failed!\n");
		return -EFAULT;
	}

	return sprintf(buf, "0x%x\n", ibattr.vendor_id);
}

static ssize_t show_device(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct virtc4iw_device *vdev =
	    container_of(dev, struct virtc4iw_device, dma_device);
	struct ib_device_attr ibattr;

	if (ib_query_device(&vdev->gdev->ibdev, &ibattr)) {
		dprint(DBG_ON, "query device failed!\n");
		return -EFAULT;
	}

	return sprintf(buf, "0x%x\n", ibattr.vendor_part_id);
}

static DEVICE_ATTR(vendor, S_IRUGO, show_vendor, NULL);
static DEVICE_ATTR(device, S_IRUGO, show_device, NULL);

static struct device_attribute *virtc4iw_dma_dev_attributes[] = {
	&dev_attr_vendor, &dev_attr_device
};

static struct ib_ucontext *virtc4iw_alloc_ucontext(struct ib_device *ibdev,
						   struct ib_udata *udata)
{
	struct ib_ucontext *ibuctx;
	struct hyv_ucontext *guctx;
	struct c4iw_alloc_ucontext_resp uresp;
	struct virtc4iw_ucontext *vuctx;
	int ret;

	dprint(DBG_IBV, "\n");

	if (!udata) {
        ret = -ENOSYS;
        goto fail;
    }

    ibuctx = hyv_ibv_alloc_ucontext(ibdev, udata);
    if (IS_ERR(ibuctx)) {
        ret = PTR_ERR(ibuctx);
        goto fail;
    }
    guctx = ibuctx_to_hyv(ibuctx);
    guctx->priv = NULL;

    if (udata->outlen < sizeof(uresp)) {
        dprint(DBG_ON, "invalid response size\n");
        ret = -EFAULT;
        goto fail_alloc_uctx;
    }
    if (copy_from_user(&uresp, udata->outbuf, sizeof(uresp))) {
        dprint(DBG_ON, "copy from udata failed\n");
        ret = -EFAULT;
        goto fail_alloc_uctx;
    }

    vuctx = kmalloc(sizeof(*vuctx), GFP_KERNEL);
    if (!vuctx) {
        dprint(DBG_ON, "alloc uctx failed\n");
        ret = -ENOMEM;
        goto fail_alloc_uctx;
    }
    guctx->priv = vuctx;

    vuctx->status_page_mmap = hyv_mmap_prepare(
        ibuctx, uresp.status_page_size, uresp.status_page_key);
    if (IS_ERR(vuctx->status_page_mmap)) {
        dprint(DBG_ON, "could not prepare mmap\n");
        ret = PTR_ERR(vuctx->status_page_mmap);
        goto fail_vuctx;
    }

	return ibuctx;
fail_vuctx:
	kfree(vuctx);
fail_alloc_uctx:
	hyv_ibv_dealloc_ucontext(ibuctx);
fail:
	return ERR_PTR(ret);
}

static int virtc4iw_dealloc_ucontext(struct ib_ucontext *ibuctx)
{
	struct hyv_ucontext *uctx = ibuctx_to_hyv(ibuctx);
	struct virtc4iw_ucontext *vuctx = uctx->priv;

	hyv_unmap(ibuctx, vuctx->status_page_mmap);

	hyv_ibv_dealloc_ucontext(ibuctx);

	kfree(vuctx);

	return 0;
}

static int virtc4iw_probe(struct hyv_device *dev)
{
	struct virtc4iw_device *vdev;
	struct ib_device *ibdev = &dev->ibdev;
	int ret;
	uint32_t i;

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

	dev_set_name(&vdev->dma_device, "virtc4iw_dma_%d", dev->index);
	vdev->dma_device.release = &virtc4iw_dma_release;
	vdev->dma_device.archdata.dma_ops = &virtc4iw_dma_generic_ops;

	ret = device_register(&vdev->dma_device);
	if (ret) {
		goto fail_vdev;
	}

	for (i = 0; i < ARRAY_SIZE(virtc4iw_dma_dev_attributes); ++i) {
		ret = device_create_file(&vdev->dma_device,
					 virtc4iw_dma_dev_attributes[i]);
		if (ret) {
			dprint(DBG_ON, "device_create_file failed!\n");
			ret = -EFAULT;
			goto fail_reg;
		}
	}

	strlcpy(ibdev->name, "vcxgb4_%d", IB_DEVICE_NAME_MAX);
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
	    (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL);
	ibdev->node_type = RDMA_NODE_RNIC;
	strcpy(ibdev->node_desc, "vcxgb4 Chelsio");
	// TODO: match with host
	ibdev->num_comp_vectors = 1;

	/* dma device */
	ibdev->dma_device = &vdev->dma_device;
	ibdev->dma_ops = &virtc4iw_dma_mapping_ops;

	ibdev->alloc_ucontext = &virtc4iw_alloc_ucontext;
	ibdev->dealloc_ucontext = &virtc4iw_dealloc_ucontext;

	ibdev->query_device = &hyv_ibv_query_device;
	ibdev->query_port = &hyv_ibv_query_port;
	ibdev->query_pkey = &virtc4iw_query_pkey;
	ibdev->query_gid = &hyv_ibv_query_gid;

	ibdev->alloc_pd = &virtc4iw_alloc_pd;
	ibdev->dealloc_pd = &hyv_ibv_dealloc_pd;

	ibdev->create_ah = &virtc4iw_ah_create;
	ibdev->destroy_ah = &virtc4iw_ah_destroy;

	ibdev->create_qp = &virtc4iw_create_qp;
	ibdev->modify_qp = &virtc4iw_modify_qp;
	ibdev->destroy_qp = &virtc4iw_destroy_qp;

	ibdev->post_send = (void *)0xDEADBEEF;
	ibdev->post_recv = (void *)0xDEADBEEF;

	ibdev->create_cq = &virtc4iw_create_cq;
	ibdev->destroy_cq = &virtc4iw_destroy_cq;

	ibdev->poll_cq = (void *)0xDEADBEEF;
	ibdev->req_notify_cq = (void *)0xDEADBEEF;

	ibdev->get_dma_mr = (void *)0xDEADBEEF;

	ibdev->reg_user_mr = &virtc4iw_reg_user_mr;
	ibdev->reg_phys_mr = (void *)0xDEADBEEF;
	ibdev->dereg_mr = &hyv_ibv_dereg_mr;

	ibdev->mmap = &hyv_ibv_mmap;

	ibdev->uverbs_abi_ver = VIRTC4IW_UVERBS_ABI_VERSION;

	ret = ib_register_device(ibdev, NULL);
	if (ret) {
		dprint(DBG_ON, "could not register device!\n");
		goto fail_reg;
	}

	for (i = 0; i < ARRAY_SIZE(virtc4iw_class_attributes); ++i) {
		ret = device_create_file(&dev->ibdev.dev,
					 virtc4iw_class_attributes[i]);
		if (ret) {
			dprint(DBG_ON, "create device file failed\n");
			goto fail_ibreg;
		}
	}

	return 0;
fail_ibreg:
	ib_unregister_device(&dev->ibdev);
fail_reg:
	device_unregister(&vdev->dma_device);
fail_vdev:
	kfree(vdev);
fail:
	return ret;
}

static int virtc4iw_remove(struct hyv_device *dev)
{
	struct virtc4iw_device *vdev = dev->priv;

	/* detach driver */
	dprint(DBG_DEV, "\n");

	ib_unregister_device(&dev->ibdev);
	dev->priv = NULL;

	device_unregister(&vdev->dma_device);

	kfree(vdev);

	return 0;
}

static struct hyv_driver virtc4iw_driver = { .driver.name = KBUILD_MODNAME,
					     .driver.owner = THIS_MODULE,
					     .id_table = id_table,
					     .probe = virtc4iw_probe,
					     .remove = virtc4iw_remove, };

static int __init init(void)
{
	return register_hyv_driver(&virtc4iw_driver);
}

static void __exit fini(void)
{
	unregister_hyv_driver(&virtc4iw_driver);
}

module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio_hyv, id_table);
MODULE_DESCRIPTION("cxgb4 virtual provider");
MODULE_LICENSE("GPL v2");
