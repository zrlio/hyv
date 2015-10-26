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

#ifndef VHOST_HYV_H_
#define VHOST_HYV_H_

#include <linux/kernel.h>
#include <linux/spinlock.h>

#include <hypercall_host.h>

#include <hyv_event.h>
#include <vhost.h>

#include "vhost_hyv_ibv.h"
#include "vhost_hyv_dev.h"

struct vhost_hyv
{
	struct vhost_dev vdev;
	struct device dev;
	struct hypercall_vq vq_hcall;
	struct vhost_virtqueue vq_evt;

	struct hyv_event_queue *evt_queue;
	u64 pfront;
	spinlock_t evt_lock;

	struct object_map devices;

	/* id to ptr maps are all global to avoid
	 * multiple lookups (we keep dependencies in local
	 * lists */
	struct object_map uctxs;
	struct object_map pds;
	struct object_map cqs;
	struct object_map qps;
	struct object_map srqs;
	struct object_map mrs;
	struct object_map mmaps;
};

static inline struct vhost_hyv *hvq_to_vg(struct hypercall_vq *hvq)
{
	return container_of(hvq, struct vhost_hyv, vq_hcall);
}

#endif /* VHOST_HYV_H_ */
