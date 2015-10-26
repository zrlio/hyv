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

#include "virtio_rdmacm_debug.h"

#include <hypercall_guest.h>
#include <rdmacm_hypercall.h>

#include <virtio_rdmacm_config.h>

DEF_HYPERCALL(VIRTIO_RDMACM_POST_EVENT, vrdmacm_post_event, __s32,
	      POST_EVENT_ARGS);

DEF_HYPERCALL(VIRTIO_RDMACM_CREATE_ID, vrdmacm_create_id, __s32,
	      CREATE_ID_ARGS);

DEF_HYPERCALL(VIRTIO_RDMACM_DESTROY_ID, vrdmacm_destroy_id, __s32,
	      DESTROY_ID_ARGS);

DEF_HYPERCALL(VIRTIO_RDMACM_RESOLVE_ADDR, vrdmacm_resolve_addr, __s32,
	      RESOLVE_ADDR_ARGS);

DEF_HYPERCALL(VIRTIO_RDMACM_RESOLVE_ROUTE, vrdmacm_resolve_route, __s32,
	      RESOLVE_ROUTE_ARGS);

DEF_HYPERCALL(VIRTIO_RDMACM_CONNECT, vrdmacm_connect, __s32, CONNECT_ARGS);
