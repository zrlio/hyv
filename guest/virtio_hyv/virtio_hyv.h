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

#ifndef _VIRTIO_HYV_H
#define _VIRTIO_HYV_H

#include <linux/virtio.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include <hypercall_guest.h>

#include <hyv_event.h>

struct virtio_hyv_vq
{
	struct virtqueue *vq;
	spinlock_t lock;
};

struct virtio_hyv
{
	struct virtio_device *vdev;
	struct hypercall_vq vq_hcall;
	struct virtio_hyv_vq vq_evt;

	struct hyv_event_queue *evt_queue;
	u64 cback;
	spinlock_t evt_lock;
};

#endif /* _VIRTIO_HYV_H */
