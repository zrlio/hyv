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

#include <rdma/rdma_cm.h>

#include <hypercall_host.h>
#include <rdmacm_hypercall.h>

#include "vhost_rdmacm_debug.h"
#include "vhost_rdmacm.h"

void vhost_rdmacm_ctx_release(struct object *obj)
{
	struct vhost_rdmacm_ctx *ctx =
	    container_of(obj, struct vhost_rdmacm_ctx, hdr);
	struct vhost_rdmacm_event *vhost_event, *tmp;

	dprint(DBG_CM, "\n");

	rdma_destroy_id(ctx->id);

	/* the event_handler cannot be called after the id has been destroyed */
	list_for_each_entry_safe(vhost_event, tmp, &ctx->events, list)
	{
		kfree(vhost_event);
	}

	kfree(ctx);
}

static int event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	struct vhost_rdmacm_ctx *ctx = id->context;
	struct vhost_rdmacm_event *vhost_event;
	vrdmacm_event vevent;
	int ret = 0;

	dprint(DBG_EVT, "id = 0x%p, event = { .event = %d, .status = %d }\n",
	       id, event->event, event->status);

	if (list_empty(&ctx->events)) {
		dprint(DBG_ON, "no preposted events?\n");
		return 0;
	}
	vhost_event =
	    list_first_entry(&ctx->events, struct vhost_rdmacm_event, list);

	list_del(&vhost_event->list);

	copy_rdmacm_event_to_virt(event, &vevent);

	if (event->event == RDMA_CM_EVENT_ADDR_RESOLVED) {
		if (!id->device) {
			dprint(DBG_ON, "address resolved but no device?\n");
			ret = -ENODEV;
			goto fail;
		}
		memcpy(&vevent.param.node_guid, &id->device->node_guid,
		       sizeof(vevent.param.node_guid));
	}

	ret = hypercall_prepare_complete(vhost_event->hcall_async);
	if (ret) {
		dprint(DBG_ON, "could not prepare complete\n");
		goto fail;
	}

	if (copy_to_user(vhost_event->event, &vevent,
			 sizeof(*vhost_event->event))) {
		dprint(DBG_ON, "could not copy to user event\n");
		ret = -EFAULT;
		goto fail;
	}

fail:
	vrdmacm_post_event_complete(vhost_event->hcall_async, ret);
	return 0;
}

DEF_HYPERCALL_ASYNC(vrdmacm_post_event, __s32, POST_EVENT_ARGS)
{
	struct vhost_rdmacm *vcm = hvq_to_vcm(hcall_async->hvq);
	struct vhost_rdmacm_ctx *ctx;
	struct vhost_rdmacm_event *vhost_event;
	int ret;

	dprint(DBG_EVT, "\n");

	ctx = object_map_id_get_entry(&vcm->ctxs, struct vhost_rdmacm_ctx, hdr,
				      ctx_handle);
	if (!ctx) {
		ret = -EINVAL;
		goto fail;
	}

	vhost_event = kmalloc(sizeof(*vhost_event), GFP_KERNEL);
	if (!vhost_event) {
		dprint(DBG_ON, "could not alloc event\n");
		ret = -ENOMEM;
		goto fail;
	}

	vhost_event->event = event;
	vhost_event->hcall_async = hcall_async;
	list_add(&vhost_event->list, &ctx->events);

	object_put(&ctx->hdr, &vhost_rdmacm_ctx_release);

	return;
fail:
	if (vrdmacm_post_event_complete(hcall_async, ret)) {
		dprint(DBG_ON, "could not complete post event\n");
		/* TODO: kill user process */
	}
}

DEF_HYPERCALL(vrdmacm_create_id, __s32, CREATE_ID_ARGS)
{
	struct vhost_rdmacm *vcm = hvq_to_vcm(hvq);
	struct vhost_rdmacm_ctx *ctx;
	int ret;

	dprint(DBG_CM, "\n");

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		dprint(DBG_ON, "alloc ctx failed\n");
		ret = -ENOMEM;
		goto fail;
	}

	ctx->vcm = vcm;
	INIT_LIST_HEAD(&ctx->events);

	ctx->id = rdma_create_id(event_handler, ctx, port_space, qp_type);
	if (IS_ERR(ctx->id)) {
		dprint(DBG_ON, "could not create id\n");
		ret = PTR_ERR(ctx->id);
		goto fail_ctx;
	}

	ret = object_map_add(&vcm->ctxs, NULL, &ctx->hdr);
	if (ret < 0) {
		goto fail_create;
	}
	ctx->id->context = ctx;

	return ret;
fail_create:
	rdma_destroy_id(ctx->id);
fail_ctx:
	kfree(ctx);
fail:
	return ret;
}

DEF_HYPERCALL(vrdmacm_destroy_id, __s32, DESTROY_ID_ARGS)
{
	struct vhost_rdmacm *vcm = hvq_to_vcm(hvq);

	dprint(DBG_CM, "\n");

	return object_map_id_del(&vcm->ctxs, ctx_handle,
				 &vhost_rdmacm_ctx_release);
}

DEF_HYPERCALL(vrdmacm_resolve_addr, __s32, RESOLVE_ADDR_ARGS)
{
	struct vhost_rdmacm *vcm = hvq_to_vcm(hvq);
	struct vhost_rdmacm_ctx *ctx;
	struct sockaddr src_addr, dst_addr;
	int ret;

	dprint(DBG_CM, "\n");

	ctx = object_map_id_get_entry(&vcm->ctxs, struct vhost_rdmacm_ctx, hdr,
				      ctx_handle);
	if (!ctx) {
		ret = -EINVAL;
		goto fail;
	}

	if (src_available) {
		if (copy_from_user(&src_addr, addr, sizeof(src_addr))) {
			dprint(DBG_ON, "could not copy from user src\n");
			ret = -EFAULT;
			goto fail_ctx_get;
		}
	}

	if (dst_available) {
		if (copy_from_user(&dst_addr, addr + 1, sizeof(dst_addr))) {
			dprint(DBG_ON, "could not copy from user dest\n");
			ret = -EFAULT;
			goto fail_ctx_get;
		}
	}

	ret = rdma_resolve_addr(ctx->id, src_available ? &src_addr : NULL,
				dst_available ? &dst_addr : NULL, timeout_ms);
	if (ret) {
		dprint(DBG_ON, "resolve addr failed (%d)\n", ret);
	}

fail_ctx_get:
	object_put(&ctx->hdr, &vhost_rdmacm_ctx_release);
fail:
	return ret;
}

DEF_HYPERCALL(vrdmacm_resolve_route, __s32, RESOLVE_ROUTE_ARGS)
{
	struct vhost_rdmacm *vcm = hvq_to_vcm(hvq);
	struct vhost_rdmacm_ctx *ctx;
	int ret;

	dprint(DBG_CM, "\n");

	ctx = object_map_id_get_entry(&vcm->ctxs, struct vhost_rdmacm_ctx, hdr,
				      ctx_handle);
	if (!ctx) {
		ret = -EINVAL;
		goto fail;
	}

	ret = rdma_resolve_route(ctx->id, timeout_ms);
	if (ret) {
		dprint(DBG_ON, "resolve route failed (%d)\n", ret);
	}

	object_put(&ctx->hdr, &vhost_rdmacm_ctx_release);
fail:
	return ret;
}

DEF_HYPERCALL(vrdmacm_connect, __s32, CONNECT_ARGS)
{
	struct vhost_rdmacm *vcm = hvq_to_vcm(hvq);
	struct vhost_rdmacm_ctx *ctx;
	struct rdma_conn_param cm_conn_param;
	vrdmacm_conn_param vconn_param;
	int ret;

	dprint(DBG_CM, "\n");

	ctx = object_map_id_get_entry(&vcm->ctxs, struct vhost_rdmacm_ctx, hdr,
				      ctx_handle);
	if (!ctx) {
		ret = -EINVAL;
		goto fail;
	}

	if (copy_from_user(&vconn_param, conn_param, sizeof(vconn_param))) {
		dprint(DBG_ON, "could not copy conn_param from user\n");
		ret = -EFAULT;
		goto fail_ctx;
	}
	copy_virt_conn_param_to_rdmacm(&vconn_param, &cm_conn_param);

	// TODO: private data support
	cm_conn_param.private_data = NULL;
	cm_conn_param.private_data_len = 0;

	ret = rdma_connect(ctx->id, &cm_conn_param);
	if (ret) {
		dprint(DBG_ON, "connect failed (%d)\n", ret);
	}

fail_ctx:
	object_put(&ctx->hdr, &vhost_rdmacm_ctx_release);
fail:
	return ret;
}
