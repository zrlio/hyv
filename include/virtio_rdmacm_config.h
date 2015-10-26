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

#ifndef VIRTIO_RDMACM_CONFIG_H_
#define VIRTIO_RDMACM_CONFIG_H_

#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/virtio_config.h>

#define VIRTIO_ID_RDMACM 0xd

#define VIRTIO_RDMACM_VQ_HCALL_SIZE 256

typedef struct VirtIORdmaCMConfig
{
} VirtIORdmaCMConfig;

enum {
	VIRTIO_RDMACM_POST_EVENT = 0,
	VIRTIO_RDMACM_CREATE_ID,
	VIRTIO_RDMACM_DESTROY_ID,
	VIRTIO_RDMACM_RESOLVE_ADDR,
	VIRTIO_RDMACM_RESOLVE_ROUTE,
	VIRTIO_RDMACM_CONNECT,
	VIRTIO_RDMACM_NHCALLS
};

#endif /* VIRTIO_RDMACM_CONFIG_H_ */
