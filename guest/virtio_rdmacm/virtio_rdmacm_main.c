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
#include <linux/moduleparam.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

#include <hypercall_guest.h>
#include <rdmacm_hypercall.h>

#include "rdmacm_ibdev.h"

#include "virtio_rdmacm.h"
#include "virtio_rdmacm_debug.h"

#include <virtio_rdmacm_config.h>

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_RDMACM, VIRTIO_DEV_ANY_ID }, { 0 },
};

struct virtio_rdmacm *g_vcm = NULL;

static int virtio_rdmacm_init_vqs(struct virtio_rdmacm *vcm)
{
	int ret;
	struct virtio_device *vdev = vcm->vdev;
	const char *name[] = { "hypercall" };
	struct virtqueue *vq;
	vq_callback_t *vq_cb;

	dprint(DBG_VIRTIO, "\n");

	vq_cb = virtio_ack_hypercall;

	ret = vdev->config->find_vqs(vdev, 1, &vq, &vq_cb, name);
	if (ret) {
		dprint(DBG_ON, "could not find vqs\n");
		return ret;
	}

	hypercall_init_vq(&vcm->vq, vq);
	return 0;
}

static int virtio_rdmacm_probe(struct virtio_device *vdev)
{
	struct virtio_rdmacm *vcm;
	int ret;

	dprint(DBG_VIRTIO, "\n");

	if (g_vcm) {
		dprint(DBG_ON, "there is already a cm device\n");
		return -EEXIST;
	}

	vdev->priv = vcm = kmalloc(sizeof(*vcm), GFP_KERNEL);
	if (!vcm) {
		ret = -ENOMEM;
		goto fail;
	}
	vcm->vdev = vdev;
	g_vcm = vcm;

	ret = virtio_rdmacm_init_vqs(vcm);
	if (ret) {
		goto fail_vcm;
	}

	return 0;
fail_vcm:
	kfree(vcm);
fail:
	return ret;
}

static void virtio_rdmacm_remove(struct virtio_device *vdev)
{
	struct virtio_rdmacm *vcm = vdev->priv;

	dprint(DBG_VIRTIO, "\n");

	hypercall_del_vq(&vcm->vq);

	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	kfree(vcm);
}

#ifdef CONFIG_PM
static int virtio_rdmacm_freeze(struct virtio_device *vdev)
{
	return 0;
}

static int virtio_rdmacm_restore(struct virtio_device *vdev)
{
	return 0;
}
#endif

static unsigned int features[] = {};

static struct virtio_driver virtio_rdmacm_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtio_rdmacm_probe,
	.remove = virtio_rdmacm_remove,
//	.config_changed = virtio_rdmacm_config_changed,
#ifdef CONFIG_PM
	.freeze = virtio_rdmacm_freeze,
	.restore = virtio_rdmacm_restore,
#endif
};

static int __init init(void)
{
	int ret;
	dprint(DBG_VIRTIO, "\n");

	ret = rdmacm_init_ibdev();
	if (ret) {
		dprint(DBG_ON, "could not init ibdev");
		goto fail;
	}

	ret = register_virtio_driver(&virtio_rdmacm_driver);
	if (ret) {
		dprint(DBG_ON, "register virtio driver failed!\n");
		goto fail_ibdev;
	}

	return 0;
fail_ibdev:
	rdmacm_exit_ibdev();
fail:
	return ret;
}

static void __exit fini(void)
{
	dprint(DBG_VIRTIO, "\n");
	rdmacm_exit_ibdev();
	unregister_virtio_driver(&virtio_rdmacm_driver);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio rdmacm driver");
MODULE_LICENSE("GPL v2");
