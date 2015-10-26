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
#include <rdma/ib.h>

#include <hypercall_guest.h>
#include <rdmacm_hypercall.h>

#include "rdmacm_ibdev.h"
#include "virtio_rdmacm_debug.h"
#include "virtio_rdmacm.h"

#define RDMACM_PREPOST_EVENTS 10

struct rdma_cm_id_priv
{
	uint32_t host_handle;
	struct rdma_cm_id id;
};

static inline struct rdma_cm_id_priv *rdmacm_id_to_priv(struct rdma_cm_id *id)
{
	return container_of(id, struct rdma_cm_id_priv, id);
}

static int post_event(struct rdma_cm_id_priv *priv_id);

static void post_event_cb(struct hypercall_vq *hvq, void *data,
			  int hcall_result, __s32 *result,
			  vrdmacm_event *vevent, uint32_t event_size)
{
	struct rdma_cm_id_priv *priv_id = data;
	struct rdma_cm_event event;

	post_event(priv_id);

	/* TODO: handle destroy of cm */
	if (hcall_result) {
		dprint(DBG_ON, "hypercall failed on host (%d)\n", hcall_result);
		goto fail;
	}

	dprint(DBG_EVT, "event = { .event = %u, .status = %d }\n",
	       vevent->event, vevent->status);

	copy_virt_event_to_rdmacm(vevent, &event);

	if (!event.status && event.event == RDMA_CM_EVENT_ADDR_RESOLVED) {
		struct ib_device *ibdev;

		dprint(DBG_EVT, "rdma addr resolved => set device\n");

		ibdev = rdmacm_get_ibdev(vevent->param.node_guid);
		if (!ibdev) {
			dprint(DBG_ON, "device does not exists (%llx)\n",
			       vevent->param.node_guid);
			event.event = RDMA_CM_EVENT_ADDR_ERROR;
		} else {
			priv_id->id.device = ibdev;
		}
	}

	if (priv_id->id.event_handler(&priv_id->id, &event)) {
		rdma_destroy_id(&priv_id->id);
	}

fail:
	kfree(vevent);
}

static int post_event(struct rdma_cm_id_priv *priv_id)
{
	int ret;
	vrdmacm_event *event;

	dprint(DBG_EVT, "\n");

	/* we might be in interrupt context */
	event = kmalloc(sizeof(*event), GFP_ATOMIC);
	if (!event) {
		dprint(DBG_ON, "could not allocate event\n");
		ret = -ENOMEM;
		goto fail;
	}

	ret = vrdmacm_post_event_async(
	    &g_vcm->vq, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_ATOMIC, &post_event_cb, priv_id, priv_id->host_handle, event,
	    sizeof(*event));
	if (ret) {
		dprint(DBG_ON, "post event hypercall failed!\n");
		goto fail_event;
	}

	return 0;
fail_event:
	kfree(event);
fail:
	return ret;
}

struct rdma_cm_id *rdma_create_id(rdma_cm_event_handler event_handler,
				  void *context, enum rdma_port_space ps,
				  enum ib_qp_type qp_type)
{
	struct rdma_cm_id_priv *priv_id;
	int ret, hret, i;

	dprint(DBG_CM, "\n");

	priv_id = kzalloc(sizeof(*priv_id), GFP_KERNEL);
	if (!priv_id) {
		dprint(DBG_ON, "could not allocate id\n");
		ret = -ENOMEM;
		goto fail;
	}

	priv_id->id.context = context;
	priv_id->id.event_handler = event_handler;
	priv_id->id.ps = ps;
	priv_id->id.qp_type = qp_type;

	ret = vrdmacm_create_id(&g_vcm->vq,
				HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
				GFP_KERNEL, &hret, (__u64)priv_id, ps, qp_type);
	if (ret || hret < 0) {
		dprint(DBG_ON, "could not create id on host\n");
		ret = ret ? ret : hret;
		goto fail_id;
	}

	priv_id->host_handle = hret;

	for (i = 0; i < RDMACM_PREPOST_EVENTS; i++) {
		post_event(priv_id);
	}

	return &priv_id->id;
fail_id:
	kfree(priv_id);
fail:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(rdma_create_id);

void rdma_destroy_id(struct rdma_cm_id *id)
{
	struct rdma_cm_id_priv *priv_id = rdmacm_id_to_priv(id);
	int ret, hret;

	dprint(DBG_CM, "\n");

	ret = vrdmacm_destroy_id(&g_vcm->vq,
				 HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
				 GFP_KERNEL, &hret, priv_id->host_handle);
	if (ret || hret) {
		dprint(DBG_ON, "could not destroy id on host\n");
	}

	if (priv_id->id.device) {
		rdmacm_put_ibdev(priv_id->id.device);
	}

	kfree(priv_id);
}
EXPORT_SYMBOL(rdma_destroy_id);

int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(rdma_bind_addr);

int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      struct sockaddr *dst_addr, int timeout_ms)
{
	struct rdma_cm_id_priv *priv_id = rdmacm_id_to_priv(id);
	int ret, hret;
	struct sockaddr *addr;

	dprint(DBG_CM, "\n");

	addr = kmalloc(sizeof(*addr) * 2, GFP_KERNEL);
	if (!addr) {
		dprint(DBG_ON, "could not alloc addr\n");
		ret = -ENOMEM;
		goto fail;
	}
	if (src_addr) {
		memcpy(addr, src_addr, sizeof(*src_addr));
	}
	if (dst_addr) {
		memcpy(addr + 1, dst_addr, sizeof(*dst_addr));
	}

	ret = vrdmacm_resolve_addr(
	    &g_vcm->vq, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, priv_id->host_handle, timeout_ms,
	    src_addr != NULL, dst_addr != NULL, addr, sizeof(*addr) * 2);
	if (ret || hret) {
		dprint(DBG_ON, "could not resolve addr on host\n");
		ret = ret ? ret : hret;
	}
	kfree(addr);

fail:
	return ret;
}
EXPORT_SYMBOL(rdma_resolve_addr);

int rdma_resolve_route(struct rdma_cm_id *id, int timeout_ms)
{
	struct rdma_cm_id_priv *priv_id = rdmacm_id_to_priv(id);
	int ret, hret;

	dprint(DBG_CM, "\n");

	ret = vrdmacm_resolve_route(
	    &g_vcm->vq, HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
	    GFP_KERNEL, &hret, priv_id->host_handle, timeout_ms);
	if (ret || hret) {
		dprint(DBG_ON, "could not resolve route on host\n");
		ret = ret ? ret : hret;
	}

	return ret;
}
EXPORT_SYMBOL(rdma_resolve_route);

int rdma_listen(struct rdma_cm_id *id, int backlog)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(rdma_listen);

int rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(rdma_accept);

int rdma_init_qp_attr(struct rdma_cm_id *id, struct ib_qp_attr *qp_attr,
		      int *qp_attr_mask)
{
	*qp_attr_mask = IB_QP_STATE | IB_QP_ACCESS_FLAGS;
	qp_attr->qp_access_flags =
	    IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ;
	return 0;
}
EXPORT_SYMBOL(rdma_init_qp_attr);

int init_ud_qp(struct rdma_cm_id *id, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IB_QPS_INIT;
	ret = rdma_init_qp_attr(id, &qp_attr, &qp_attr_mask);
	if (ret) {
		dprint(DBG_ON, "init qp attr failed\n");
		goto fail;
	}

	ret = ib_modify_qp(qp, &qp_attr, qp_attr_mask);
	if (ret) {
		dprint(DBG_ON, "modify qp failed (INIT)\n");
		goto fail;
	}

	qp_attr.qp_state = IB_QPS_RTR;
	ret = ib_modify_qp(qp, &qp_attr, IB_QP_STATE);
	if (ret) {
		dprint(DBG_ON, "modify qp failed (RTR)");
		goto fail;
	}

	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 0;
	ret = ib_modify_qp(qp, &qp_attr, IB_QP_STATE | IB_QP_SQ_PSN);
	if (ret) {
		dprint(DBG_ON, "modify qp failed (RTS)");
	}
fail:
	return ret;
}

int init_conn_qp(struct rdma_cm_id *id, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IB_QPS_INIT;
	ret = rdma_init_qp_attr(id, &qp_attr, &qp_attr_mask);
	if (ret) {
		dprint(DBG_ON, "init qp attr failed\n");
		goto fail;
	}

	ret = ib_modify_qp(qp, &qp_attr, qp_attr_mask);
	if (ret) {
		dprint(DBG_ON, "modify qp failed (INIT)\n");
	}
fail:
	return ret;
}

int rdma_create_qp(struct rdma_cm_id *id, struct ib_pd *pd,
		   struct ib_qp_init_attr *qp_init_attr)
{
	int ret;
	struct ib_qp *qp;

	if (id->device != pd->device) {
		dprint(DBG_ON, "bound device does not match pd device\n");
		ret = -EINVAL;
		goto fail;
	}

	if (id->qp) {
		dprint(DBG_ON, "a QP is already associated with this id\n");
		ret = -EINVAL;
		goto fail;
	}

	qp = ib_create_qp(pd, qp_init_attr);
	if (IS_ERR(qp)) {
		dprint(DBG_ON, "could not create qp\n");
		ret = PTR_ERR(qp);
		goto fail;
	}

	if (id->qp_type == IB_QPT_UD) {
		ret = init_ud_qp(id, qp);
	} else {
		ret = init_conn_qp(id, qp);
	}

	if (ret) {
		goto fail_create_qp;
	}

	id->qp = qp;

	return 0;
fail_create_qp:
	ib_destroy_qp(qp);
fail:
	return ret;
}
EXPORT_SYMBOL(rdma_create_qp);

void rdma_destroy_qp(struct rdma_cm_id *id)
{
	ib_destroy_qp(id->qp);
	id->qp = NULL;
}
EXPORT_SYMBOL(rdma_destroy_qp);

int rdma_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	struct rdma_cm_id_priv *priv_id = rdmacm_id_to_priv(id);
	vrdmacm_conn_param *vconn_param;
	int ret, hret;

	dprint(DBG_CM, "\n");

	vconn_param = kmalloc(sizeof(*vconn_param), GFP_KERNEL);
	if (!vconn_param) {
		dprint(DBG_ON, "could not allocate conn param\n");
		ret = -ENOMEM;
		goto fail;
	}

	if (id->qp) {
		conn_param->qp_num = id->qp->qp_num;
		conn_param->srq = id->qp->srq != NULL;
	}

	copy_rdmacm_conn_param_to_virt(conn_param, vconn_param);

	ret = vrdmacm_connect(&g_vcm->vq,
			      HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
			      GFP_KERNEL, &hret, priv_id->host_handle,
			      vconn_param, sizeof(*vconn_param));
	if (ret || hret) {
		dprint(DBG_ON, "could not connect on host\n");
		ret = ret ? ret : hret;
	}

	kfree(vconn_param);

	return 0;
fail:
	return ret;
}
EXPORT_SYMBOL(rdma_connect);

int rdma_disconnect(struct rdma_cm_id *id)
{
	return 0;
}
EXPORT_SYMBOL(rdma_disconnect);
