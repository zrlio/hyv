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

#ifndef VHOST_HYV_DEV_H_
#define VHOST_HYV_DEV_H_

#include <object_map.h>

struct ib_device;

struct vhost_hyv_device
{
	struct object hdr;

	struct device dev;
	bool removed;
	struct ib_device *ibdev;
	struct vhost_hyv *vg;

	struct list_head uctxs;
};

void vhost_hyv_device_release(struct object *obj);

ssize_t vhost_hyv_add_device(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count);

#endif /* VHOST_HYV_DEV_H_ */
