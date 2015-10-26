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

#ifndef HYV_HYPERCALL_H_
#define HYV_HYPERCALL_H_

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>

typedef struct
{
	__u32 in;
	__u32 out;
	__u8 data[0];
} hyv_udata;

typedef struct
{
	__u64 addr;
	__u64 size;
} hyv_user_mem_chunk;

typedef struct
{
	__u32 type;
	__u32 udata_offset;
	__u32 n_chunks;
	hyv_user_mem_chunk chunk[0];
} hyv_udata_translate;

#define OPEN_DEV_ARGS(copy_arg, ptr_arg) copy_arg(__u32, dev_handle)
DECL_HYPERCALL(hyv_get_ib_device, __s32, OPEN_DEV_ARGS);

#define CLOSE_DEV_ARGS(copy_arg, ptr_arg) copy_arg(__u32, dev_handle)
DECL_HYPERCALL(hyv_put_ib_device, __s32, CLOSE_DEV_ARGS);

typedef struct ib_uverbs_query_device_resp hyv_query_device_result;

#define QUERY_DEV_ARGS(copy_arg, ptr_arg)                                      \
	copy_arg(__u32, dev_handle)                                            \
	    ptr_arg(hyv_query_device_result *, attr, attr_size)
DECL_HYPERCALL(hyv_ibv_query_deviceX, __s32, QUERY_DEV_ARGS);

typedef struct ib_uverbs_query_port_resp hyv_query_port_result;

#define QUERY_PORT_ARGS(copy_arg, ptr_arg)                                     \
	copy_arg(__u32, dev_handle) copy_arg(__u8, port_num)                   \
	    ptr_arg(hyv_query_port_result *, attr, attr_size)
DECL_HYPERCALL(hyv_ibv_query_portX, __s32, QUERY_PORT_ARGS);

#define QUERY_PKEY_ARGS(copy_arg, ptr_arg)                                     \
	copy_arg(__u32, dev_handle) copy_arg(__u8, port) copy_arg(__s32, index)
DECL_HYPERCALL(hyv_ibv_query_pkeyX, __s32, QUERY_PKEY_ARGS);

typedef struct
{
	__u8 raw[16];
} hyv_query_gid_result;

#define QUERY_GID_ARGS(copy_arg, ptr_arg)                                      \
	copy_arg(__u32, dev_handle) copy_arg(__u8, port)                       \
	    copy_arg(__s32, index)                                             \
	    ptr_arg(hyv_query_gid_result *, gid, gid_size)
DECL_HYPERCALL(hyv_ibv_query_gidX, __s32, QUERY_GID_ARGS);

#define ALLOC_UCTX_ARGS(copy_arg, ptr_arg)                                     \
	copy_arg(__u32, dev_handle) ptr_arg(hyv_udata *, udata, udata_size)
DECL_HYPERCALL(hyv_ibv_alloc_ucontextX, __s32, ALLOC_UCTX_ARGS);

#define DEALLOC_UCTX_ARGS(copy_arg, ptr_arg) copy_arg(__u32, uctx_handle)
DECL_HYPERCALL(hyv_ibv_dealloc_ucontextX, __s32, DEALLOC_UCTX_ARGS);

#define ALLOC_PD_ARGS(copy_arg, ptr_arg)                                       \
	copy_arg(__u32, uctx_handle) ptr_arg(hyv_udata *, udata, udata_size)
DECL_HYPERCALL(hyv_ibv_alloc_pdX, __s32, ALLOC_PD_ARGS);

#define DEALLOC_PD_ARGS(copy_arg, ptr_arg) copy_arg(__u32, pd_handle)
DECL_HYPERCALL(hyv_ibv_dealloc_pdX, __s32, DEALLOC_PD_ARGS);

typedef struct
{
	__s32 cq_handle;
	__s32 cqe;
} hyv_create_cq_result;

#define CREATE_CQ_ARGS(copy_arg, ptr_arg)                                      \
	copy_arg(__u64, guest_handle) copy_arg(__u32, uctx_handle)             \
	    copy_arg(__s32, entries) copy_arg(__s32, vector)                   \
	    ptr_arg(hyv_udata *, udata, udata_size) ptr_arg(                   \
		hyv_udata_translate *, udata_translate, udata_translate_size)
DECL_HYPERCALL(hyv_ibv_create_cqX, hyv_create_cq_result, CREATE_CQ_ARGS);

#define DESTROY_CQ_ARGS(copy_arg, ptr_arg) copy_arg(__u32, cq_handle)
DECL_HYPERCALL(hyv_ibv_destroy_cqX, __s32, DESTROY_CQ_ARGS);

typedef struct
{
	__u32 max_send_wr;
	__u32 max_recv_wr;
	__u32 max_send_sge;
	__u32 max_recv_sge;
	__u32 max_inline_data;
} hyv_qp_cap;

static inline void copy_hyv_qp_cap_to_ib(const hyv_qp_cap *gcap,
					 struct ib_qp_cap *ibcap)
{
	ibcap->max_send_wr = gcap->max_send_wr;
	ibcap->max_recv_wr = gcap->max_recv_wr;
	ibcap->max_send_sge = gcap->max_send_sge;
	ibcap->max_recv_sge = gcap->max_recv_sge;
	ibcap->max_inline_data = gcap->max_inline_data;
}

static inline void copy_ib_qp_cap_to_hyv(const struct ib_qp_cap *ibcap,
					 hyv_qp_cap *gcap)
{
	gcap->max_send_wr = ibcap->max_send_wr;
	gcap->max_recv_wr = ibcap->max_recv_wr;
	gcap->max_send_sge = ibcap->max_send_sge;
	gcap->max_recv_sge = ibcap->max_recv_sge;
	gcap->max_inline_data = ibcap->max_inline_data;
}

typedef struct
{
	__u32 qp_handle;
	__u32 qpn;
	hyv_qp_cap cap;
} hyv_create_qp_result;

typedef struct
{
	__s32 send_cq_handle;
	__s32 recv_cq_handle;
	__s32 srq_handle;
	__s32 xrcd_handle;
	hyv_qp_cap cap;
	__u32 sq_sig_type;
	__u32 qp_type;
	__u32 create_flags;
	__u8 port_num;
} hyv_qp_init_attr;

#define CREATE_QP_ARGS(copy_arg, ptr_arg)                                      \
	copy_arg(__u64, guest_handle) copy_arg(__u32, pd_handle)               \
	    copy_arg(hyv_qp_init_attr, init_attr)                              \
	    ptr_arg(hyv_create_qp_result *, res, res_size)                     \
	    ptr_arg(hyv_udata *, udata, udata_size) ptr_arg(                   \
		hyv_udata_translate *, udata_translate, udata_translate_size)
DECL_HYPERCALL(hyv_ibv_create_qpX, __s32, CREATE_QP_ARGS);

typedef struct
{
	__u8 raw_gid[16];
	__u32 flow_label;
	__u8 sgid_index;
	__u8 hop_limit;
	__u8 traffic_class;
} hyv_global_route;

typedef struct
{
	hyv_global_route grh;
	__u16 dlid;
	__u8 sl;
	__u8 src_path_bits;
	__u8 static_rate;
	__u8 ah_flags;
	__u8 port_num;
} hyv_ah_attr;

static inline void copy_hyv_ah_attr_to_ib(const hyv_ah_attr *gahattr,
					  struct ib_ah_attr *ibahattr)
{
	memcpy(ibahattr->grh.dgid.raw, gahattr->grh.raw_gid,
	       sizeof(ibahattr->grh.dgid.raw));
	ibahattr->grh.flow_label = gahattr->grh.flow_label;
	ibahattr->grh.sgid_index = gahattr->grh.sgid_index;
	ibahattr->grh.hop_limit = gahattr->grh.hop_limit;
	ibahattr->grh.traffic_class = gahattr->grh.traffic_class;

	ibahattr->dlid = gahattr->dlid;
	ibahattr->sl = gahattr->sl;
	ibahattr->src_path_bits = gahattr->src_path_bits;
	ibahattr->static_rate = gahattr->static_rate;
	ibahattr->ah_flags = gahattr->ah_flags;
	ibahattr->port_num = gahattr->port_num;
}

static inline void copy_ib_ah_attr_to_hyv(const struct ib_ah_attr *ibahattr,
					  hyv_ah_attr *gahattr)
{
	memcpy(gahattr->grh.raw_gid, ibahattr->grh.dgid.raw,
	       sizeof(gahattr->grh.raw_gid));
	gahattr->grh.flow_label = ibahattr->grh.flow_label;
	gahattr->grh.sgid_index = ibahattr->grh.sgid_index;
	gahattr->grh.hop_limit = ibahattr->grh.hop_limit;
	gahattr->grh.traffic_class = ibahattr->grh.traffic_class;

	gahattr->dlid = ibahattr->dlid;
	gahattr->sl = ibahattr->sl;
	gahattr->src_path_bits = ibahattr->src_path_bits;
	gahattr->static_rate = ibahattr->static_rate;
	gahattr->ah_flags = ibahattr->ah_flags;
	gahattr->port_num = ibahattr->port_num;
}

typedef struct
{
	__u32 qp_state;
	__u32 cur_qp_state;
	__u32 path_mtu;
	__u32 path_mig_state;
	__u32 qkey;
	__u32 rq_psn;
	__u32 sq_psn;
	__u32 dest_qp_num;
	__s32 qp_access_flags;
	hyv_qp_cap cap;
	hyv_ah_attr ah_attr;
	hyv_ah_attr alt_ah_attr;
	__u16 pkey_index;
	__u16 alt_pkey_index;
	__u8 en_sqd_async_notify;
	__u8 sq_draining;
	__u8 max_rd_atomic;
	__u8 max_dest_rd_atomic;
	__u8 min_rnr_timer;
	__u8 port_num;
	__u8 timeout;
	__u8 retry_cnt;
	__u8 rnr_retry;
	__u8 alt_port_num;
	__u8 alt_timeout;
} hyv_qp_attr;

static inline void copy_hyv_qp_attr_to_ib(const hyv_qp_attr *attr,
					  struct ib_qp_attr *ibattr)
{
	ibattr->qp_state = attr->qp_state;
	ibattr->cur_qp_state = attr->cur_qp_state;
	ibattr->path_mtu = attr->path_mtu;
	ibattr->path_mig_state = attr->path_mig_state;
	ibattr->qkey = attr->qkey;
	ibattr->rq_psn = attr->rq_psn;
	ibattr->sq_psn = attr->sq_psn;
	ibattr->dest_qp_num = attr->dest_qp_num;
	ibattr->qp_access_flags = attr->qp_access_flags;
	copy_hyv_qp_cap_to_ib(&attr->cap, &ibattr->cap);
	copy_hyv_ah_attr_to_ib(&attr->ah_attr, &ibattr->ah_attr);
	copy_hyv_ah_attr_to_ib(&attr->alt_ah_attr, &ibattr->alt_ah_attr);
	ibattr->pkey_index = attr->pkey_index;
	ibattr->alt_pkey_index = attr->alt_pkey_index;
	ibattr->en_sqd_async_notify = attr->en_sqd_async_notify;
	ibattr->max_rd_atomic = attr->max_rd_atomic;
	ibattr->max_dest_rd_atomic = attr->max_dest_rd_atomic;
	ibattr->min_rnr_timer = attr->min_rnr_timer;
	ibattr->port_num = attr->port_num;
	ibattr->timeout = attr->timeout;
	ibattr->retry_cnt = attr->retry_cnt;
	ibattr->rnr_retry = attr->rnr_retry;
	ibattr->alt_port_num = attr->alt_port_num;
	ibattr->alt_timeout = attr->alt_timeout;
}

static inline void copy_ib_qp_attr_to_hyv(const struct ib_qp_attr *ibattr,
					  hyv_qp_attr *attr)
{
	attr->qp_state = ibattr->qp_state;
	attr->cur_qp_state = ibattr->cur_qp_state;
	attr->path_mtu = ibattr->path_mtu;
	attr->path_mig_state = ibattr->path_mig_state;
	attr->qkey = ibattr->qkey;
	attr->rq_psn = ibattr->rq_psn;
	attr->sq_psn = ibattr->sq_psn;
	attr->dest_qp_num = ibattr->dest_qp_num;
	attr->qp_access_flags = ibattr->qp_access_flags;
	copy_ib_qp_cap_to_hyv(&ibattr->cap, &attr->cap);
	copy_ib_ah_attr_to_hyv(&ibattr->ah_attr, &attr->ah_attr);
	copy_ib_ah_attr_to_hyv(&ibattr->alt_ah_attr, &attr->alt_ah_attr);
	attr->pkey_index = ibattr->pkey_index;
	attr->alt_pkey_index = ibattr->alt_pkey_index;
	attr->en_sqd_async_notify = ibattr->en_sqd_async_notify;
	attr->max_rd_atomic = ibattr->max_rd_atomic;
	attr->max_dest_rd_atomic = ibattr->max_dest_rd_atomic;
	attr->min_rnr_timer = ibattr->min_rnr_timer;
	attr->port_num = ibattr->port_num;
	attr->timeout = ibattr->timeout;
	attr->retry_cnt = ibattr->retry_cnt;
	attr->rnr_retry = ibattr->rnr_retry;
	attr->alt_port_num = ibattr->alt_port_num;
	attr->alt_timeout = ibattr->alt_timeout;
}

#define MODIFY_QP_ARGS(copy_arg, ptr_arg)                                      \
	copy_arg(__u32, qp_handle) copy_arg(hyv_qp_attr, attr)                 \
	    copy_arg(__u32, attr_mask) ptr_arg(hyv_udata *, udata, udata_size)
DECL_HYPERCALL(hyv_ibv_modify_qpX, __s32, MODIFY_QP_ARGS);

#define QUERY_QP_ARGS(copy_arg, ptr_arg)                                       \
	copy_arg(__u32, qp_handle) copy_arg(__u32, attr_mask)                  \
	    ptr_arg(hyv_qp_attr *, attr, attr_size)                            \
	    ptr_arg(hyv_qp_init_attr *, init_attr, init_attr_size)
DECL_HYPERCALL(hyv_ibv_query_qpX, __s32, QUERY_QP_ARGS);

#define DESTROY_QP_ARGS(copy_arg, ptr_arg) copy_arg(__u32, qp_handle)
DECL_HYPERCALL(hyv_ibv_destroy_qpX, __s32, DESTROY_QP_ARGS);

typedef struct
{
	__u32 max_wr;
	__u32 max_sge;
	__u32 srq_limit;
} hyv_srq_attr;

typedef struct
{
	__s32 srq_handle;
	__u32 max_wr;
	__u32 max_sge;
} hyv_create_srq_result;

#define CREATE_SRQ_ARGS(copy_arg, ptr_arg)                                     \
	copy_arg(__u64, guest_handle) copy_arg(__u32, pd_handle)               \
	    copy_arg(hyv_srq_attr, attr) copy_arg(__u32, srq_type)             \
	    copy_arg(__s32, cq_handle) copy_arg(__s32, xrcd_handle)            \
	    ptr_arg(hyv_udata *, udata, udata_size) ptr_arg(                   \
		hyv_udata_translate *, udata_translate, udata_translate_size)
DECL_HYPERCALL(hyv_ibv_create_srqX, hyv_create_srq_result, CREATE_SRQ_ARGS);

#define MODIFY_SRQ_ARGS(copy_arg, ptr_arg)                                     \
	copy_arg(__u32, srq_handle) copy_arg(hyv_srq_attr, attr)               \
	    copy_arg(__u32, attr_mask) ptr_arg(hyv_udata *, udata, udata_size)
DECL_HYPERCALL(hyv_ibv_modify_srqX, __s32, MODIFY_SRQ_ARGS);

#define DESTROY_SRQ_ARGS(copy_arg, ptr_arg) copy_arg(__u32, srq_handle)
DECL_HYPERCALL(hyv_ibv_destroy_srqX, __s32, DESTROY_SRQ_ARGS);

typedef struct
{
	__s32 mr_handle;
	__u32 lkey;
	__u32 rkey;
} hyv_reg_user_mr_result;

#define REG_USER_MR_ARGS(copy_arg, ptr_arg)                                    \
	copy_arg(__u32, pd_handle) copy_arg(__u64, user_va)                    \
	    copy_arg(__u64, size) copy_arg(__s32, access)                      \
	    ptr_arg(hyv_user_mem_chunk *, mem_chunk, chunk_size)               \
	    ptr_arg(hyv_udata *, udata, udata_size) ptr_arg(                   \
		hyv_udata_translate *, udata_translate, udata_translate_size)
DECL_HYPERCALL(hyv_ibv_reg_user_mrX, hyv_reg_user_mr_result, REG_USER_MR_ARGS);

#define DEREG_MR_ARGS(copy_arg, ptr_arg) copy_arg(__u32, mr_handle)
DECL_HYPERCALL(hyv_ibv_dereg_mrX, __s32, DEREG_MR_ARGS);

typedef struct
{
	__s32 mmap_handle;
	__u64 pgprot;
} hyv_mmap_result;

#define POST_SEND_ARGS(copy_arg, ptr_arg) copy_arg(__u32, qp_handle)
DECL_HYPERCALL(hyv_ibv_post_send_nullX, __s32, POST_SEND_ARGS);

#define MMAP_ARGS(copy_arg, ptr_arg)                                           \
	copy_arg(__u32, uctx_handle) copy_arg(__u64, phys_addr)                \
	    copy_arg(__u32, size) copy_arg(__u64, vm_flags)                    \
	    copy_arg(__u64, vm_pgoff)
DECL_HYPERCALL(hyv_mmap, hyv_mmap_result, MMAP_ARGS);

#define MUNMAP_ARGS(copy_arg, ptr_arg) copy_arg(__u32, mmap_handle)
DECL_HYPERCALL(hyv_munmap, __s32, MUNMAP_ARGS);

#endif /* HYV_HYPERCALL_H_ */
