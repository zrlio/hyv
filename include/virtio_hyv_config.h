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

#ifndef VIRTIO_HYV_CONFIG_H_
#define VIRTIO_HYV_CONFIG_H_

#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/virtio_config.h>

#define VIRTIO_ID_HYV 0xe

/* We would like to include linux/vhost.h but qemu vhost-scsi does not
 * handle this properly */
#define VHOST_VIRTIO 0xAF
#define VHOST_HYV_ADD_DEVS _IO(VHOST_VIRTIO, 0xe0)

#define VIRTIO_HYV_VQ_HCALL_SIZE 256

typedef struct VirtIOHyvConfig
{
} VirtIOHyvConfig;

enum {
	VIRTIO_HYV_VQ_HCALL = 0,
	VIRTIO_HYV_VQ_EVT,
	VIRTIO_HYV_NVQS
};

enum {
	VIRTIO_HYV_GET_IB_DEV = 0,
	VIRTIO_HYV_PUT_IB_DEV,
	VIRTIO_HYV_MMAP,
	VIRTIO_HYV_MUNMAP,
	VIRTIO_HYV_IBV_QUERY_DEV,
	VIRTIO_HYV_IBV_QUERY_PORT,
	VIRTIO_HYV_IBV_QUERY_PKEY,
	VIRTIO_HYV_IBV_QUERY_GID,
	VIRTIO_HYV_IBV_ALLOC_UCTX,
	VIRTIO_HYV_IBV_DEALLOC_UCTX,
	VIRTIO_HYV_IBV_ALLOC_PD,
	VIRTIO_HYV_IBV_DEALLOC_PD,
	VIRTIO_HYV_IBV_CREATE_CQ,
	VIRTIO_HYV_IBV_DESTROY_CQ,
	VIRTIO_HYV_IBV_CREATE_QP,
	VIRTIO_HYV_IBV_MODIFY_QP,
	VIRTIO_HYV_IBV_QUERY_QP,
	VIRTIO_HYV_IBV_DESTROY_QP,
	VIRTIO_HYV_IBV_CREATE_SRQ,
	VIRTIO_HYV_IBV_MODIFY_SRQ,
	VIRTIO_HYV_IBV_DESTROY_SRQ,
	VIRTIO_HYV_IBV_REG_USER_MR,
	VIRTIO_HYV_IBV_DEREG_MR,
	VIRTIO_HYV_IBV_POST_SEND_NULL,
	VIRTIO_HYV_NHCALLS
};

#endif /* VIRTIO_HYV_CONFIG_H_ */
