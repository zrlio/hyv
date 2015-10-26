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

#ifndef HYPERCALL_HOST_H_
#define HYPERCALL_HOST_H_

#include <hypercall.h>

#include <linux/mmu_context.h>
#include <vhost.h>

struct hypercall_vq;
struct hypercall_async;

typedef int (*hypercall_t)(struct hypercall_vq *hvq, struct iovec iov[]);
typedef int (*hypercall_async_t)(struct hypercall_async *hcall_async,
				 struct iovec iov[]);

struct hypercall
{
	hypercall_t func;
	hypercall_async_t async_func;
	uint32_t npargs;
	uint32_t copy_arg_size;
	uint32_t return_size;
};

struct hypercall_async
{
	struct vhost_work work;
	struct hypercall_vq *hvq;
	mm_segment_t oldfs;
	int head;
	uint32_t flags;
	struct hypercall_ret_header __user *hret;
};

struct hypercall_vq
{
	struct vhost_virtqueue vq;
	const struct hypercall *const *hypercall;
	uint32_t hcall_num;
};

#define HYPERCALL_FUNC(name, ret_type, args)                                   \
	static inline ret_type name(                                           \
	    struct hypercall_vq *hvq args(ARG_DEF, ARG_PTR_DEF))
#define HYPERCALL_FUNC_ASYNC(name, ret_type, args)                             \
	void name##_async(                                                     \
	    struct hypercall_async *hcall_async args(ARG_DEF, ARG_PTR_DEF))

#define HYPERCALL_FUNC_ASYNC_COMPLETE(name, ret_type, args)                    \
	int name##_complete(struct hypercall_async *hcall_async,               \
			    ret_type ret_value)

#define DECL_HYPERCALL(name, ret_type, args)                                   \
	extern const struct hypercall hypercall_##name;                        \
	HYPERCALL_COPY_ARGS(name, args);                                       \
	HYPERCALL_RESULT(name, ret_type);                                      \
	HYPERCALL_FUNC_ASYNC_COMPLETE(name, ret_type, args)

#define ARG_PTR_DEF(a, b, c) , a __user b, uint32_t c
#define ARG_PTR_VAR(a, b, c)                                                   \
	a __user b;                                                            \
	uint32_t c;

#define ARG_CALL(a, b) , _args.copy_args.b
#define ARG_PTR_CALL(a, b, c) , _args.b, _args.c

#define ARG_PTR_ASSIGN(a, b, c)                                                \
	_args.b = (a __user)iov[++i].iov_base;                                 \
	_args.c = iov[i].iov_len;

/* At this point we have macros for either sync or async but this might
 * change in the future */
#define DEF_HYPERCALL(name, ret_type, args)                                    \
	HYPERCALL_FUNC(name, ret_type, args);                                  \
	static int _##name(struct hypercall_vq *hvq, struct iovec iov[])       \
	{                                                                      \
		uint32_t i = 0;                                                \
		ret_type ret_value;                                            \
		struct name##_result __user *ures;                             \
		struct                                                         \
		{                                                              \
			struct name##_copy_args copy_args;                     \
			args(VOID, ARG_PTR_VAR);                               \
		} _args;                                                       \
		if (copy_from_user(&_args, iov[i].iov_base,                    \
				   sizeof(_args.copy_args))) {                 \
			return -EFAULT;                                        \
		}                                                              \
		args(VOID, ARG_PTR_ASSIGN);                                    \
		ret_value = name(hvq args(ARG_CALL, ARG_PTR_CALL));            \
		ures = (struct name##_result __user *)iov[++i].iov_base;       \
		if (copy_to_user(&ures->value, &ret_value,                     \
				 sizeof(ret_value))) {                         \
			return -EFAULT;                                        \
		}                                                              \
		return 0;                                                      \
	}                                                                      \
	const struct hypercall hypercall_##name = {                            \
		_##name,		     NULL,                             \
		0 args(VOID, ARG_COUNT),     sizeof(struct name##_copy_args),  \
		sizeof(struct name##_result)                                   \
	};                                                                     \
	HYPERCALL_FUNC(name, ret_type, args)

#define DEF_HYPERCALL_ASYNC(name, ret_type, args)                              \
	HYPERCALL_FUNC_ASYNC(name, ret_type, args);                            \
	static int _##name##_async(struct hypercall_async *hcall_async,        \
				   struct iovec iov[])                         \
	{                                                                      \
		uint32_t i = 0;                                                \
		struct                                                         \
		{                                                              \
			struct name##_copy_args copy_args;                     \
			args(VOID, ARG_PTR_VAR);                               \
		} _args;                                                       \
		if (copy_from_user(&_args, iov[i].iov_base,                    \
				   sizeof(_args.copy_args))) {                 \
			return -EFAULT;                                        \
		}                                                              \
		args(VOID, ARG_PTR_ASSIGN);                                    \
		name##_async(hcall_async args(ARG_CALL, ARG_PTR_CALL));        \
		return 0;                                                      \
	}                                                                      \
	const struct hypercall hypercall_##name = {                            \
		NULL,			     _##name##_async,                  \
		0 args(VOID, ARG_COUNT),     sizeof(struct name##_copy_args),  \
		sizeof(struct name##_result)                                   \
	};                                                                     \
	HYPERCALL_FUNC_ASYNC_COMPLETE(name, ret_type, args)                    \
	{                                                                      \
		int ret = 0;                                                   \
		struct vhost_virtqueue *vq = &hcall_async->hvq->vq;            \
		struct name##_result __user *ures;                             \
		ures = (struct name##_result __user *)hcall_async->hret;       \
		if (copy_to_user(&ures->hdr.value, &ret,                       \
				 sizeof(ures->hdr.value))) {                   \
			return -EFAULT;                                        \
		}                                                              \
		if (copy_to_user(&ures->value, &ret_value,                     \
				 sizeof(ret_value))) {                         \
			return -EFAULT;                                        \
		}                                                              \
		unuse_mm(vq->dev->mm);                                         \
		set_fs(hcall_async->oldfs);                                    \
		vhost_work_queue(vq->dev, &hcall_async->work);                 \
		return 0;                                                      \
	}                                                                      \
	HYPERCALL_FUNC_ASYNC(name, ret_type, args)

void hypercall_init_vq(struct hypercall_vq *hvq,
		       const struct hypercall *const *hcall,
		       uint32_t hcall_num);

int hypercall_prepare_complete(struct hypercall_async *hcall_async);

#endif /* HYPERCALL_HOST_H_ */
