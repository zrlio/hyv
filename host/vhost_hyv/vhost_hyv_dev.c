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

#include <linux/types.h>

#include "vhost_hyv_debug.h"
#include "vhost_hyv_ibdev.h"
#include "vhost_hyv_ibv.h"
#include "vhost_hyv_event.h"
#include "vhost_hyv.h"

#include <hypercall_host.h>
#include <hyv_hypercall.h>

#include "vhost_hyv_dev.h"

void vhost_hyv_device_release(struct object *obj)
{
	struct vhost_hyv_device *gdev =
	    container_of(obj, struct vhost_hyv_device, hdr);
	struct vhost_hyv_ucontext *uctx, *tmp;

	dprint(DBG_DEV, "\n");

	/* force release all uctxs */
	list_for_each_entry_safe(uctx, tmp, &gdev->uctxs, hdr.list)
	{
		dprint(DBG_ON, "unreleased uctx (%d) -> force release\n",
		       uctx->hdr.id);
		vhost_hyv_ucontext_release(&uctx->hdr);
	}

	if (!gdev->removed) {
		device_unregister(&gdev->dev);
	}

	vhost_hyv_put_ibdev(gdev->ibdev);

	kfree(gdev);
}

DEF_HYPERCALL(hyv_get_ib_device, __s32, OPEN_DEV_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct object *obj;

	dprint(DBG_DEV, "\n");

	obj = object_map_id_get(&vg->devices, dev_handle);
	if (!obj) {
		dprint(DBG_ON, "failed to get device\n");
		return -EINVAL;
	}

	return 0;
}

DEF_HYPERCALL(hyv_put_ib_device, __s32, CLOSE_DEV_ARGS)
{
	struct vhost_hyv *vg = hvq_to_vg(hvq);
	struct vhost_hyv_device *gdev;

	dprint(DBG_DEV, "\n");

	gdev = object_map_id_get_entry(&vg->devices, struct vhost_hyv_device,
				       hdr, dev_handle);
	if (!gdev) {
		dprint(DBG_ON, "failed to put device\n");
		return -EINVAL;
	}
	object_put(&gdev->hdr, &vhost_hyv_device_release);
	return 0;
}

ssize_t store_remove_device(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct vhost_hyv_device *gdev;
	struct vhost_hyv *vg;

	dprint(DBG_DEV, "\n");

	gdev = dev_get_drvdata(dev);
	if (!gdev) {
		return -ENODEV;
	}
	vg = gdev->vg;

	gdev->removed = true;
	device_unregister(&gdev->dev);

	if (vg->evt_queue) {
		struct hyv_event event = { .type = HYV_EVENT_REM_DEVICE,
					   .id = gdev->hdr.id, };
		vhost_hyv_push_event(vg, event, true);
	}

	object_map_del(&gdev->hdr, &vhost_hyv_device_release);
	return count;
}
static DEVICE_ATTR(remove, S_IWUGO, NULL, store_remove_device);

ssize_t show_stat_uctx(struct device *dev, struct device_attribute *attr,
		       char *buf)
{
	struct vhost_hyv_device *gdev;
	struct list_head *list;
	uint32_t count = 0;

	gdev = dev_get_drvdata(dev);
	if (!gdev) {
		dprint(DBG_ON, "driver data empty\n");
		return -ENODEV;
	}

	spin_lock(&gdev->hdr.map->lock);
	list_for_each(list, &gdev->uctxs)
	{
		count++;
	}
	spin_unlock(&gdev->hdr.map->lock);

	return sprintf(buf, "%u\n", count);
}
static DEVICE_ATTR(uctxs, S_IRUGO, show_stat_uctx, NULL);

const struct device_attribute *dev_attrs[] = { &dev_attr_remove,
					       &dev_attr_uctxs, };

void vhost_hyv_gdev_release(struct device *dev)
{
	/* nothing to do here! */
	dprint(DBG_DEV, "\n");
}

ssize_t vhost_hyv_add_device(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	uint16_t s_guid[4];
	uint64_t node_guid = 0;
	unsigned long i;
	struct vhost_hyv *vg;
	struct ib_device *ibdev;
	struct vhost_hyv_device *gdev;
	int ret;

	dprint(DBG_DEV, "\n");

	vg = dev_get_drvdata(dev);
	if (!vg) {
		ret = -ENODEV;
		goto fail;
	}

	ret = sscanf(buf, "%4hx:%4hx:%4hx:%4hx", &s_guid[0], &s_guid[1],
		     &s_guid[2], &s_guid[3]);
	if (ret != 4) {
		dprint(DBG_ON, "Invalid GID\n");
		ret = -EINVAL;
		goto fail;
	}

	for (i = 0; i < 4; i++) {
		node_guid = (node_guid << 16) | s_guid[i];
	}
	/* into network byte order */
	node_guid = cpu_to_be64(node_guid);

	ibdev = vhost_hyv_get_ibdev(node_guid);
	if (!ibdev) {
		dprint(DBG_ON, "could not find device with GUID %llx\n",
		       node_guid);
		ret = -ENODEV;
		goto fail;
	}

	gdev = kzalloc(sizeof(*gdev), GFP_KERNEL);
	if (!gdev) {
		dprint(DBG_ON, "could not allocate hyv device\n");
		ret = -ENOMEM;
		goto fail_get_ibdev;
	}
	gdev->ibdev = ibdev;
	gdev->vg = vg;
	INIT_LIST_HEAD(&gdev->uctxs);

	gdev->dev.parent = &vg->dev;
	gdev->dev.release = &vhost_hyv_gdev_release;
	dev_set_name(&gdev->dev, "%04hx:%04hx:%04hx:%04hx", s_guid[0],
		     s_guid[1], s_guid[2], s_guid[3]);
	ret = device_register(&gdev->dev);
	if (ret) {
		dprint(DBG_ON, "could not register device\n");
		goto fail_gdev;
	}

	dev_set_drvdata(&gdev->dev, gdev);

	for (i = 0; i < ARRAY_SIZE(dev_attrs); i++) {
		ret = device_create_file(&gdev->dev, dev_attrs[i]);
		if (ret) {
			dprint(DBG_ON, "could not create file (%s)\n",
			       dev_attrs[i]->attr.name);
			goto fail_devreg;
		}
	}

	ret = object_map_add(&vg->devices, NULL, &gdev->hdr);
	if (ret < 0) {
		goto fail_devreg;
	}

	if (vg->evt_queue) {
		struct hyv_event event = { .type = HYV_EVENT_ADD_DEVICE,
					   .id = ret, };
		vhost_hyv_push_event(vg, event, true);
	}

	dprint(DBG_DEV, "%llx\n", ibdev->node_guid);

	return count;
fail_devreg:
	device_unregister(&gdev->dev);
fail_gdev:
	kfree(gdev);
fail_get_ibdev:
	vhost_hyv_put_ibdev(ibdev);
fail:
	return ret;
}
