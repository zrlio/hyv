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

#ifndef HYPERCALL_H_
#define HYPERCALL_H_

#include <linux/types.h>
#include <linux/virtio.h>

#define ARG_DEF(a, b) , a b
#define ARG_VAR(a, b) a b;
#define ARG_COUNT(...) +1
#define VOID(...)

struct hypercall_header
{
	__u32 id : 22;
	__u32 async : 1;
	__u32 flags : 9;
};

struct hypercall_ret_header
{
	__s32 value;
};

enum hypercall_flags {
	/* host */
	HYPERCALL_SIGNAL_GUEST = (1),
	/* guest */
	HYPERCALL_NOTIFY_HOST = (1 << 1)
};

#define HYPERCALL_MAX_PTR_ARGS 6

#define HYPERCALL_COPY_ARGS(name, args)                                        \
	struct name##_copy_args                                                \
	{                                                                      \
		struct hypercall_header hdr;                                   \
		args(ARG_VAR, VOID)                                            \
	}

#define HYPERCALL_RESULT(name, ret_type)                                       \
	struct name##_result                                                   \
	{                                                                      \
		struct hypercall_ret_header hdr;                               \
		ret_type value;                                                \
	}

#endif /* HYPERCALL_H_ */
