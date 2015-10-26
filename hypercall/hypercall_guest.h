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

#ifndef HYPERCALL_GUEST_H_
#define HYPERCALL_GUEST_H_

#include <linux/scatterlist.h>
#include <linux/spinlock.h>

#include <hypercall.h>

#define ARG_PTR_DEF(a, b, c) , a b, uint32_t c
#define ARG_PTR_VAR(a, b, c)                                                   \
	a __kernel b;                                                          \
	uint32_t c;

struct hypercall_vq
{
	struct virtqueue *vq;
	void *priv;
	spinlock_t lock;
};

void virtio_ack_hypercall(struct virtqueue *vq);

void hypercall_init_vq(struct hypercall_vq *hvq, struct virtqueue *vq);
void hypercall_del_vq(struct hypercall_vq *hvq);

#define HYPERCALL_FUNC(name, ret_type, args)                                   \
	inline int name(struct hypercall_vq *hvq, enum hypercall_flags flags,  \
			gfp_t mem_flags,                                       \
			ret_type *result args(ARG_DEF, ARG_PTR_DEF))

#define HYPERCALL_FUNC_ASYNC(name, ret_type, args)                             \
	inline int name##_async(struct hypercall_vq *hvq,                      \
				enum hypercall_flags flags, gfp_t mem_flags,   \
				name##_callback cb,                            \
				void *data args(ARG_DEF, ARG_PTR_DEF))

#define DECL_HYPERCALL(name, ret_type, args)                                   \
	typedef void (*name##_callback)(                                       \
	    struct hypercall_vq *hvq, void *data, int hcall_result,            \
	    ret_type *result args(VOID, ARG_PTR_DEF));                         \
	HYPERCALL_COPY_ARGS(name, args);                                       \
	HYPERCALL_RESULT(name, ret_type);                                      \
	HYPERCALL_FUNC(name, ret_type, args);                                  \
	HYPERCALL_FUNC_ASYNC(name, ret_type, args)

struct hypercall_parg
{
	void __kernel *ptr;
	uint32_t size;
};

struct hypercall
{
	u32 async;
};

struct hypercall_sync
{
	struct hypercall base;
	struct completion completion;
};

struct hypercall_async
{
	struct hypercall base;
	void (*cbw)(struct hypercall_vq *hvq,
		    struct hypercall_async *hcall_async);
	void *cb;
	void *data;
	struct hypercall_ret_header *hret;
	struct hypercall_parg *pargs;
};

int do_hypercall_sync(struct hypercall_vq *hvq,
		      const struct hypercall_header *hdr, uint32_t copy_size,
		      const struct hypercall_parg *pargs, uint32_t npargs,
		      struct hypercall_ret_header *hret, uint32_t result_size);

int do_hypercall_async(struct hypercall_vq *hvq,
		       struct hypercall_async *hcall_async,
		       const struct hypercall_header *hdr, uint32_t copy_size,
		       uint32_t npargs, uint32_t result_size);

#define ARG_ASSIGN(a, b) memcpy(&_args->copy_args.b, &b, sizeof(b));
#define ARG_PTR_ASSIGN(a, b, c)                                                \
	_args->pargs[i++] = (struct hypercall_parg) { b, c };
#define ARG_PTR_ASSIGN2(a, b, c)                                               \
	_args.b = (a __kernel)hcall_async->pargs[i].ptr;                       \
	_args.c = hcall_async->pargs[i++].size;

#define ARG_PTR_INIT(a, b, c)                                                  \
	{                                                                      \
		b, c                                                           \
	}                                                                      \
	,

#define ARG_PTR_CALL(a, b, c) , _args.b, _args.c

/* id is not in declartion because hypercall declaration might be used
 * by different virtio devices, i.e. different IDs */
#define DEF_HYPERCALL(host_id, name, ret_type, args)                           \
	HYPERCALL_FUNC(name, ret_type, args)                                   \
	{                                                                      \
		int ret;                                                       \
		const struct hypercall_parg pargs[] = { args(VOID,             \
							     ARG_PTR_INIT) };  \
		struct                                                         \
		{                                                              \
			struct name##_copy_args copy_args;                     \
			struct name##_result result;                           \
		} *_args;                                                      \
		_args = kmalloc(sizeof(*_args), mem_flags);                    \
		if (!_args) {                                                  \
			return -ENOMEM;                                        \
		}                                                              \
		_args->copy_args.hdr =                                         \
		    (struct hypercall_header) { host_id, 0, flags };           \
		args(ARG_ASSIGN, VOID);                                        \
		ret = do_hypercall_sync(hvq, &_args->copy_args.hdr,            \
					sizeof(_args->copy_args), pargs,       \
					ARRAY_SIZE(pargs), &_args->result.hdr, \
					sizeof(_args->result));                \
		if (!ret)                                                      \
			memcpy(result, &_args->result.value, sizeof(*result)); \
		kfree(_args);                                                  \
		return ret;                                                    \
	}                                                                      \
	inline void name##_callback_wrapper(                                   \
	    struct hypercall_vq *hvq, struct hypercall_async *hcall_async)     \
	{                                                                      \
		uint32_t i __attribute__((unused)) = 0;                        \
		struct                                                         \
		{                                                              \
			args(VOID, ARG_PTR_VAR);                               \
		} __attribute__((unused)) _args;                               \
		name##_callback cb = hcall_async->cb;                          \
		struct name##_result *result =                                 \
		    (struct name##_result *)hcall_async->hret;                 \
		args(VOID, ARG_PTR_ASSIGN2);                                   \
		cb(hvq, hcall_async->data, result->hdr.value,                  \
		   &result->value args(VOID, ARG_PTR_CALL));                   \
	}                                                                      \
	HYPERCALL_FUNC_ASYNC(name, ret_type, args)                             \
	{                                                                      \
		int ret;                                                       \
		uint32_t i = 0;                                                \
		struct                                                         \
		{                                                              \
			struct hypercall_async hcall_async;                    \
			struct name##_copy_args copy_args;                     \
			struct name##_result result;                           \
			struct hypercall_parg pargs[0 args(VOID, ARG_COUNT)];  \
		} *_args;                                                      \
		_args = kmalloc(sizeof(*_args), mem_flags);                    \
		if (!_args) {                                                  \
			return -ENOMEM;                                        \
		}                                                              \
		_args->hcall_async.cbw = &name##_callback_wrapper;             \
		_args->hcall_async.cb = cb;                                    \
		_args->hcall_async.data = data;                                \
		_args->hcall_async.hret = &_args->result.hdr;                  \
		_args->hcall_async.pargs = _args->pargs;                       \
		args(VOID, ARG_PTR_ASSIGN);                                    \
		_args->copy_args.hdr =                                         \
		    (struct hypercall_header) { host_id, 1, flags };           \
		args(ARG_ASSIGN, VOID);                                        \
		ret = do_hypercall_async(                                      \
		    hvq, &_args->hcall_async, &_args->copy_args.hdr,           \
		    sizeof(_args->copy_args), i, sizeof(_args->result));       \
		return ret;                                                    \
	}

#endif /* HYPERCALL_GUEST_H_ */
