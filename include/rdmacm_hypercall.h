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

#ifndef RDMACM_HYPERCALL_H_
#define RDMACM_HYPERCALL_H_

#include <rdma/rdma_cm.h>

typedef struct
{
	__u8 responder_resources;
	__u8 initiator_depth;
	__u8 flow_control;
	__u8 retry_count;
	__u8 rnr_retry_count;
	__u8 srq;
	__u32 qp_num;
	__u32 qkey;
} vrdmacm_conn_param;

static inline void
copy_virt_conn_param_to_rdmacm(const vrdmacm_conn_param *vconn_param,
			       struct rdma_conn_param *conn_param)
{
	conn_param->responder_resources = vconn_param->responder_resources;
	conn_param->initiator_depth = vconn_param->initiator_depth;
	conn_param->flow_control = vconn_param->flow_control;
	conn_param->retry_count = vconn_param->retry_count;
	conn_param->rnr_retry_count = vconn_param->rnr_retry_count;
	conn_param->srq = vconn_param->srq;
	conn_param->qp_num = vconn_param->qp_num;
	conn_param->qkey = vconn_param->qkey;
}

static inline void
copy_rdmacm_conn_param_to_virt(const struct rdma_conn_param *conn_param,
			       vrdmacm_conn_param *vconn_param)
{
	vconn_param->responder_resources = conn_param->responder_resources;
	vconn_param->initiator_depth = conn_param->initiator_depth;
	vconn_param->flow_control = conn_param->flow_control;
	vconn_param->retry_count = conn_param->retry_count;
	vconn_param->rnr_retry_count = conn_param->rnr_retry_count;
	vconn_param->srq = conn_param->srq;
	vconn_param->qp_num = conn_param->qp_num;
	vconn_param->qkey = conn_param->qkey;
}

typedef struct
{
	__u32 event;
	__s32 status;
	union
	{
		vrdmacm_conn_param conn;
		__be64 node_guid;
	} param;
} vrdmacm_event;

static inline void copy_virt_event_to_rdmacm(const vrdmacm_event *vevent,
					     struct rdma_cm_event *event)
{
	event->event = vevent->event;
	event->status = vevent->status;
}

static inline void copy_rdmacm_event_to_virt(const struct rdma_cm_event *event,
					     vrdmacm_event *vevent)
{
	vevent->event = event->event;
	vevent->status = event->status;
}

#define POST_EVENT_ARGS(copy_arg, ptr_arg)                                     \
	copy_arg(__u32, ctx_handle) ptr_arg(vrdmacm_event *, event, event_size)
DECL_HYPERCALL(vrdmacm_post_event, __s32, POST_EVENT_ARGS);

#define CREATE_ID_ARGS(copy_arg, ptr_arg)                                      \
	copy_arg(__u64, guest_handle) copy_arg(__u32, port_space)              \
	    copy_arg(__u32, qp_type)
DECL_HYPERCALL(vrdmacm_create_id, __s32, CREATE_ID_ARGS);

#define DESTROY_ID_ARGS(copy_arg, ptr_arg) copy_arg(__u32, ctx_handle)
DECL_HYPERCALL(vrdmacm_destroy_id, __s32, DESTROY_ID_ARGS);

#define RESOLVE_ADDR_ARGS(copy_arg, ptr_arg)                                   \
	copy_arg(__u32, ctx_handle) copy_arg(__s32, timeout_ms)                \
	    copy_arg(__u32, src_available) copy_arg(__u32, dst_available)      \
	    ptr_arg(struct sockaddr *, addr, addr_size)
DECL_HYPERCALL(vrdmacm_resolve_addr, __s32, RESOLVE_ADDR_ARGS);

#define RESOLVE_ROUTE_ARGS(copy_arg, ptr_arg)                                  \
	copy_arg(__u32, ctx_handle) copy_arg(__s32, timeout_ms)
DECL_HYPERCALL(vrdmacm_resolve_route, __s32, RESOLVE_ROUTE_ARGS);

#define CONNECT_ARGS(copy_arg, ptr_arg)                                        \
	copy_arg(__u32, ctx_handle)                                            \
	    ptr_arg(vrdmacm_conn_param *, conn_param, conn_param_size)
DECL_HYPERCALL(vrdmacm_connect, __s32, CONNECT_ARGS);

#endif /* RDMACM_HYPERCALL_H_ */
