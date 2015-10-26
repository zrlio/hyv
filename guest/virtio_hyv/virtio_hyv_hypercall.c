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

#include "virtio_hyv_debug.h"

#include <hypercall_guest.h>
#include <hyv_hypercall.h>

#include <virtio_hyv_config.h>

DEF_HYPERCALL(VIRTIO_HYV_GET_IB_DEV, hyv_get_ib_device, __s32, OPEN_DEV_ARGS);
DEF_HYPERCALL(VIRTIO_HYV_PUT_IB_DEV, hyv_put_ib_device, __s32, CLOSE_DEV_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_QUERY_DEV, hyv_ibv_query_deviceX, __s32,
	      QUERY_DEV_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_QUERY_PORT, hyv_ibv_query_portX, __s32,
	      QUERY_PORT_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_QUERY_PKEY, hyv_ibv_query_pkeyX, __s32,
	      QUERY_PKEY_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_QUERY_GID, hyv_ibv_query_gidX, __s32,
	      QUERY_GID_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_ALLOC_UCTX, hyv_ibv_alloc_ucontextX, __s32,
	      ALLOC_UCTX_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_DEALLOC_UCTX, hyv_ibv_dealloc_ucontextX, __s32,
	      DEALLOC_UCTX_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_ALLOC_PD, hyv_ibv_alloc_pdX, __s32, ALLOC_PD_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_DEALLOC_PD, hyv_ibv_dealloc_pdX, __s32,
	      DEALLOC_PD_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_CREATE_CQ, hyv_ibv_create_cqX,
	      hyv_create_cq_result, CREATE_CQ_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_DESTROY_CQ, hyv_ibv_destroy_cqX, __s32,
	      DESTROY_CQ_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_CREATE_QP, hyv_ibv_create_qpX, __s32,
	      CREATE_QP_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_MODIFY_QP, hyv_ibv_modify_qpX, __s32,
	      MODIFY_QP_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_QUERY_QP, hyv_ibv_query_qpX, __s32, QUERY_QP_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_DESTROY_QP, hyv_ibv_destroy_qpX, __s32,
	      DESTROY_QP_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_CREATE_SRQ, hyv_ibv_create_srqX,
	      hyv_create_srq_result, CREATE_SRQ_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_MODIFY_SRQ, hyv_ibv_modify_srqX, __s32,
	      MODIFY_SRQ_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_DESTROY_SRQ, hyv_ibv_destroy_srqX, __s32,
	      DESTROY_SRQ_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_REG_USER_MR, hyv_ibv_reg_user_mrX,
	      hyv_reg_user_mr_result, REG_USER_MR_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_DEREG_MR, hyv_ibv_dereg_mrX, __s32, DEREG_MR_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_IBV_POST_SEND_NULL, hyv_ibv_post_send_nullX, __s32,
	      POST_SEND_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_MMAP, hyv_mmap, hyv_mmap_result, MMAP_ARGS);

DEF_HYPERCALL(VIRTIO_HYV_MUNMAP, hyv_munmap, __s32, MUNMAP_ARGS);
