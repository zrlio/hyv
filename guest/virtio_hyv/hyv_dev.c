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
#include <linux/idr.h>

#include "virtio_hyv_debug.h"
#include "virtio_hyv.h"

#include <virtio_hyv_config.h>
#include <hyv_hypercall.h>

#include <hyv.h>

static DEFINE_IDA(hyv_index_ida);

static int hyv_dev_match(struct device *dev, struct device_driver *drv)
{
	struct hyv_device *gdev = dev_to_hyv(dev);
	struct hyv_driver *gdrv = drv_to_hyv(drv);
	uint32_t i;

	dprint(DBG_BUS, "match { %d, %d }\n", gdev->id.vendor, gdev->id.device);

	/* match ID */
	for (i = 0; gdrv->id_table[i].device; i++) {
		dprint(DBG_BUS, "id_table { %d, %d }\n",
		       gdrv->id_table[i].vendor, gdrv->id_table[i].device);
		if (gdrv->id_table[i].vendor == gdev->id.vendor &&
		    gdrv->id_table[i].device == gdev->id.device) {
			return true;
		}
	}

	return false;
}

static int hyv_dev_probe(struct device *dev)
{
	struct hyv_device *gdev = dev_to_hyv(dev);
	struct hyv_driver *gdrv = drv_to_hyv(gdev->dev.driver);
	int ret;

	ret = gdrv->probe(gdev);
	if (ret) {
		dprint(DBG_ON, "hyv driver probe failed!\n");
	}

	return ret;
}

static int hyv_dev_remove(struct device *dev)
{
	struct hyv_device *gdev = dev_to_hyv(dev);
	struct hyv_driver *gdrv = drv_to_hyv(gdev->dev.driver);

	gdrv->remove(gdev);

	return 0;
}

static struct bus_type hyv_bus = { .name = "hyv",
				   .match = hyv_dev_match,
				   //		.dev_groups =
				   // virtio_hyv_dev_groups,
				   .probe = hyv_dev_probe,
				   .remove = hyv_dev_remove, };

int register_hyv_driver(struct hyv_driver *drv)
{
	dprint(DBG_BUS, "\n");

	drv->driver.bus = &hyv_bus;
	return driver_register(&drv->driver);
}
EXPORT_SYMBOL(register_hyv_driver);

void unregister_hyv_driver(struct hyv_driver *drv)
{
	dprint(DBG_BUS, "\n");

	driver_unregister(&drv->driver);
}
EXPORT_SYMBOL(unregister_hyv_driver);

static void hyv_release_dev(struct device *dev)
{
	struct hyv_device *gdev = container_of(dev, struct hyv_device, dev);
	int ret, hret;

	/* close device on host */
	ret = hyv_put_ib_device(&gdev->vg->vq_hcall,
				HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
				GFP_KERNEL, &hret, gdev->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not put device on host\n");
	}

	ib_dealloc_device(&gdev->ibdev);
}

int register_hyv_device(struct virtio_hyv *vg, uint32_t host_handle)
{
	int ret;
	int hret;
	hyv_query_device_result attr;
	struct hyv_device *dev;

	dprint(DBG_BUS, "\n");

	dev = (struct hyv_device *)ib_alloc_device(sizeof(*dev));
	if (!dev) {
		dprint(DBG_ON, "could not allocate hyv device!\n");
		ret = -ENOMEM;
		goto fail;
	}
	dev->vg = vg;
	dev->host_handle = host_handle;
	dev->dev.release = &hyv_release_dev;

	/* open device on host */
	ret = hyv_get_ib_device(&dev->vg->vq_hcall,
				HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
				GFP_KERNEL, &hret, dev->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not get device on host\n");
		ret = ret ? ret : hret;
		goto fail_alloc;
	}

	dev->dev.bus = &hyv_bus;

	/* query device */
	ret = hyv_ibv_query_deviceX(
	    &dev->vg->vq_hcall, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, dev->host_handle, &attr, sizeof(attr));
	if (ret || hret) {
		dprint(DBG_ON, "could not query device on host\n");
		ret = ret ? ret : hret;
		goto fail_get;
	}

	/* ib device initialization */
	dev->ibdev.node_guid = attr.node_guid;
	dev->ibdev.phys_port_cnt = attr.phys_port_cnt;

	/* use vendor/device id to match driver */
	dev->id.vendor = attr.vendor_id;
	dev->id.device = attr.vendor_part_id;

	ret = ida_simple_get(&hyv_index_ida, 0, 0, GFP_KERNEL);
	if (ret < 0) {
		dprint(DBG_ON, "assign unique index failed!\n");
		goto fail_get;
	}

	dev->index = ret;
	dev_set_name(&dev->dev, "hyv%d", dev->index);

	ret = device_register(&dev->dev);
	if (ret) {
		put_device(&dev->dev);
		dprint(DBG_ON, "failed to register device!\n");
		goto fail_get;
	}

	return 0;
fail_get:
	ret = hyv_put_ib_device(&dev->vg->vq_hcall,
				HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
				GFP_KERNEL, &hret, dev->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not put device on host\n");
	}
fail_alloc:
	ib_dealloc_device(&dev->ibdev);
fail:
	return ret;
}

void unregister_hyv_device(struct hyv_device *dev)
{
	int index = dev->index;

	dprint(DBG_BUS, "\n");

	device_unregister(&dev->dev);
	ida_simple_remove(&hyv_index_ida, index);
}

int hyv_bus_for_each_dev(int (*cb)(struct device *, void *), void *data)
{
	return bus_for_each_dev(&hyv_bus, NULL, data, cb);
}

int hyv_bus_init(void)
{
	dprint(DBG_BUS, "\n");
	if (bus_register(&hyv_bus)) {
		dprint(DBG_ON, "bus registration failed!\n");
	}
	return 0;
}

void hyv_bus_exit(void)
{
	dprint(DBG_BUS, "\n");
	/* unregister all devices */
	bus_unregister(&hyv_bus);
}
