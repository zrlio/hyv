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
#include <hyv_hypercall.h>

#include "virtio_hyv.h"
#include "virtio_hyv_debug.h"
#include "virtio_hyv_event.h"

#include <virtio_hyv_config.h>
#include <hyv.h>

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_HYV, VIRTIO_DEV_ANY_ID }, { 0 },
};

static int virtio_hyv_init_vqs(struct virtio_hyv *vg)
{
	int ret;
	struct virtio_device *vdev = vg->vdev;
	const char *name[] = { "hypercall", "event" };
	struct virtqueue *vqs[VIRTIO_HYV_NVQS];
	vq_callback_t *vq_cb[VIRTIO_HYV_NVQS];

	dprint(DBG_VIRTIO, "\n");

	vq_cb[VIRTIO_HYV_VQ_HCALL] = virtio_ack_hypercall;
	vq_cb[VIRTIO_HYV_VQ_EVT] = virtio_hyv_ack_event;

	spin_lock_init(&vg->vq_evt.lock);

	ret = vdev->config->find_vqs(vdev, VIRTIO_HYV_NVQS, vqs, vq_cb, name);
	if (ret) {
		dprint(DBG_ON, "could not find vqs\n");
		return ret;
	}

	hypercall_init_vq(&vg->vq_hcall, vqs[VIRTIO_HYV_VQ_HCALL]);
	vqs[VIRTIO_HYV_VQ_EVT]->priv = vg;
	vg->vq_evt.vq = vqs[VIRTIO_HYV_VQ_EVT];

	return 0;
}

static int virtio_hyv_probe(struct virtio_device *vdev)
{
	struct virtio_hyv *vg;
	int err;

	dprint(DBG_VIRTIO, "\n");

	vdev->priv = vg = kmalloc(sizeof(*vg), GFP_KERNEL);
	if (!vg) {
		err = -ENOMEM;
		goto fail;
	}
	vg->vdev = vdev;
	vg->cback = 0;

	virtio_hyv_init_vqs(vg);
	if ((err = virtio_hyv_create_event_queue(vg))) {
		goto fail_vg;
	}

	return 0;
fail_vg:
	kfree(vg);
fail:
	return err;
}

static void virtio_hyv_remove(struct virtio_device *vdev)
{
	struct virtio_hyv *vg = vdev->priv;

	dprint(DBG_VIRTIO, "\n");

	hypercall_del_vq(&vg->vq_hcall);

	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	virtio_hyv_destroy_event_queue(vg);

	kfree(vg);
}

#ifdef CONFIG_PM
static int virtio_hyv_freeze(struct virtio_device *vdev)
{
	return 0;
}

static int virtio_hyv_restore(struct virtio_device *vdev)
{
	return 0;
}
#endif

static unsigned int features[] = {};

static struct virtio_driver virtio_hyv_driver = { .feature_table = features,
						  .feature_table_size =
						      ARRAY_SIZE(features),
						  .driver.name = KBUILD_MODNAME,
						  .driver.owner = THIS_MODULE,
						  .id_table = id_table,
						  .probe = virtio_hyv_probe,
						  .remove = virtio_hyv_remove,
//	.config_changed = virtio_hyv_config_changed,
#ifdef CONFIG_PM
						  .freeze = virtio_hyv_freeze,
						  .restore = virtio_hyv_restore,
#endif
};

int hyv_bus_init(void);
void hyv_bus_exit(void);

static int __init init(void)
{
	int ret;
	dprint(DBG_VIRTIO, "\n");

	ret = hyv_bus_init();
	if (ret) {
		dprint(DBG_ON, "failed to init virtio hyv!\n");
		goto fail;
	}
	ret = register_virtio_driver(&virtio_hyv_driver);
	if (ret) {
		dprint(DBG_ON, "register virtio driver failed!\n");
		goto fail_bus;
	}

	return 0;
fail_bus:
	hyv_bus_exit();
fail:
	return ret;
}

static void __exit fini(void)
{
	dprint(DBG_VIRTIO, "\n");
	unregister_virtio_driver(&virtio_hyv_driver);
	hyv_bus_exit();
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio hyv driver");
MODULE_LICENSE("GPL v2");
