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

#ifndef HYV_H_
#define HYV_H_

#include <linux/types.h>
#include <rdma/ib_verbs.h>

struct hyv_device_id
{
	__u32 device;
	__u32 vendor;
};

struct hyv_device;

struct hyv_driver
{
	struct device_driver driver;
	const struct hyv_device_id *id_table;
	int (*probe)(struct hyv_device *dev);
	int (*remove)(struct hyv_device *dev);
};

struct hyv_device
{
	struct ib_device ibdev;

	int index;
	struct device dev;
	/* device id to match with hyv driver */
	struct hyv_device_id id;

	struct virtio_hyv *vg;
	uint32_t host_handle;

	void *priv;
};

struct hyv_ucontext
{
	struct ib_ucontext ibuctx;

	struct list_head mmap_list;
	spinlock_t mmap_lock;
	uint32_t host_handle;

	void *priv;
};

struct hyv_mmap
{
	struct list_head list;

	void *addr;
	size_t size;
	uint32_t key;

	bool mapped;
	uint32_t host_handle;
};

struct hyv_pd
{
	struct ib_pd ibpd;

	uint32_t host_handle;

	struct hyv_mr_cache *dma_mr_cache;

	void *priv;
};

struct hyv_cq
{
	struct ib_cq ibcq;

	uint32_t host_handle;

	/* these are translated udata pointers */
	struct hyv_user_mem **umem;
	unsigned long n_umem;

	void *priv;
};

struct hyv_qp
{
	struct ib_qp ibqp;

	uint32_t host_handle;

	/* these are translated udata pointers */
	struct hyv_user_mem **umem;
	unsigned long n_umem;

	void *priv;
};

struct hyv_srq
{
	struct ib_srq ibsrq;

	uint32_t host_handle;

	/* these are translated udata pointers */
	struct hyv_user_mem **umem;
	unsigned long n_umem;

	void *priv;
};

struct hyv_mr
{
	struct hlist_node node;

	struct ib_mr ibmr;

	/* we need this for kverbs dma mrs */
	u64 iova;
	u64 size;
	int access;

	struct hyv_user_mem **umem;
	unsigned long n_umem;

	uint32_t host_handle;

	void *priv;
};

static inline struct hyv_mr *ibmr_to_hyv(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct hyv_mr, ibmr);
}

static inline struct hyv_srq *ibsrq_to_hyv(struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct hyv_srq, ibsrq);
}

static inline struct hyv_qp *ibqp_to_hyv(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct hyv_qp, ibqp);
}

static inline struct hyv_cq *ibcq_to_hyv(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct hyv_cq, ibcq);
}

static inline struct hyv_pd *ibpd_to_hyv(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct hyv_pd, ibpd);
}

static inline struct hyv_ucontext *ibuctx_to_hyv(struct ib_ucontext *ibuctx)
{
	return container_of(ibuctx, struct hyv_ucontext, ibuctx);
}

static inline struct hyv_device *dev_to_hyv(struct device *dev)
{
	return container_of(dev, struct hyv_device, dev);
}

static inline struct hyv_device *ibdev_to_hyv(struct ib_device *ibdev)
{
	return container_of(ibdev, struct hyv_device, ibdev);
}

static inline struct hyv_driver *drv_to_hyv(struct device_driver *drv)
{
	return container_of(drv, struct hyv_driver, driver);
}

int register_hyv_driver(struct hyv_driver *drv);
void unregister_hyv_driver(struct hyv_driver *drv);

int register_hyv_device(struct virtio_hyv *vg, uint32_t host_handle);
void unregister_hyv_device(struct hyv_device *dev);

int hyv_bus_for_each_dev(int (*cb)(struct device *, void *), void *data);

/* IBV */

enum hyv_udata_gvm_type {
	HYV_IB_UMEM,
	HYV_COPY_FROM_GUEST,
	HYV_COPY_TO_GUEST
};

struct hyv_udata_gvm
{
	enum hyv_udata_gvm_type type;

	/* offset into user cmd */
	unsigned long udata_offset;
	unsigned long mask;
	unsigned long size;
};

int hyv_ibv_query_device(struct ib_device *ibdev, struct ib_device_attr *props);

int hyv_ibv_query_port(struct ib_device *ibdev, u8 port,
		       struct ib_port_attr *ibattr);

int hyv_ibv_query_pkey(struct ib_device *ibdev, u8 port, u16 index, u16 *pkey);

int hyv_ibv_query_gid(struct ib_device *ibdev, u8 port, int index,
		      union ib_gid *ibgid);

struct ib_ucontext *hyv_ibv_alloc_ucontext(struct ib_device *ibdev,
					   struct ib_udata *udata);

int hyv_ibv_dealloc_ucontext(struct ib_ucontext *uctx);

struct ib_pd *hyv_ibv_alloc_pd(struct ib_device *ibdev,
			       struct ib_ucontext *ibuctx,
			       struct ib_udata *udata);

int hyv_ibv_dealloc_pd(struct ib_pd *ibpd);

struct ib_cq *hyv_ibv_create_cq_gv2hv(struct ib_device *ibdev, int entries,
				      int vector, struct ib_ucontext *ibuctx,
				      struct ib_udata *ibudata,
				      struct hyv_udata_gvm *udata_gvm,
				      uint32_t udata_gvm_num);

struct ib_cq *hyv_ibv_create_cq(struct ib_device *ibdev, int entries,
				int vector, struct ib_ucontext *ibuctx,
				struct ib_udata *udata);

int hyv_ibv_destroy_cq(struct ib_cq *ib_cq);

struct ib_qp *hyv_ibv_create_qp_gv2hv(struct ib_pd *ibpd,
				      struct ib_qp_init_attr *attr,
				      struct ib_udata *ibudata,
				      struct hyv_udata_gvm *udata_gvm,
				      uint32_t udata_gvm_num);

struct ib_qp *hyv_ibv_create_qp(struct ib_pd *ibpd,
				struct ib_qp_init_attr *attr,
				struct ib_udata *udata);

int hyv_ibv_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *ibattr,
		      int attr_mask, struct ib_udata *udata);

int hyv_ibv_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *ibattr,
		     int attr_mask, struct ib_qp_init_attr *ibinit_attr);

int hyv_ibv_destroy_qp(struct ib_qp *ibqp);

struct ib_srq *hyv_ibv_create_srq_gv2hv(struct ib_pd *ibpd,
					struct ib_srq_init_attr *attr,
					struct ib_udata *ibudata,
					struct hyv_udata_gvm *udata_gvm,
					uint32_t udata_gvm_num);

struct ib_srq *hyv_ibv_create_srq(struct ib_pd *ibpd,
				  struct ib_srq_init_attr *attr,
				  struct ib_udata *ibudata);

int hyv_ibv_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *ibattr,
		       enum ib_srq_attr_mask attr_mask,
		       struct ib_udata *ibudata);

int hyv_ibv_destroy_srq(struct ib_srq *ibsrq);

struct ib_mr *hyv_ibv_reg_user_mr_gv2hv(struct ib_pd *ibpd, u64 user_va,
					u64 size, u64 io_va, int access,
					struct ib_udata *udata,
					struct hyv_udata_gvm *udata_gvm,
					uint32_t udata_gvm_num);

struct ib_mr *hyv_ibv_reg_user_mr(struct ib_pd *ibpd, u64 user_va, u64 size,
				  u64 io_va, int access,
				  struct ib_udata *udata);

int hyv_ibv_dereg_mr(struct ib_mr *ibmr);

int hyv_ibv_mmap(struct ib_ucontext *ibuctx, struct vm_area_struct *vma);

int hyv_ibv_post_send_null(struct ib_qp *ibqp);

/* KVERBS */

int hyv_kverbs_prepare_post_send(struct ib_qp *qp, struct ib_send_wr *send_wr,
				 struct ib_send_wr **bad_send_wr);

int hyv_kverbs_prepare_post_recv(struct ib_qp *qp, struct ib_recv_wr *recv_wr,
				 struct ib_recv_wr **bad_recv_wr);

int hyv_kverbs_init_pd(struct ib_pd *ibpd);

struct ib_mr *hyv_ibv_reg_phys_mr(struct ib_pd *ibpd,
				  struct ib_phys_buf *phys_buf_array,
				  int num_phys_buf, int mr_access_flags,
				  u64 *iova_start, struct ib_udata *ibudata);

int hyv_kverbs_mmap(struct ib_ucontext *ibuctx, struct hyv_mmap *gmm,
		    unsigned long vm_flags);

/* MEM */

struct hyv_mmap *hyv_mmap_alloc(uint32_t size, uint32_t key);

struct hyv_mmap *hyv_mmap_prepare(struct ib_ucontext *ibuctx, uint32_t size,
				  uint32_t key);

void hyv_mmap_unprepare(struct ib_ucontext *ibuctx, struct hyv_mmap *mm);

int hyv_unmap(struct ib_ucontext *ibuctx, struct hyv_mmap *mm);

#endif /* HYV_H_ */
