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

#ifndef LLQUEUE_H_
#define LLQUEUE_H_

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/atomic.h>

/* This is a lock-free single-consumer/producer
 * fixed sized queue implementation
 * (cf. "Correct and Efficient Bounded FIFO Queues" SBAC-PAD 2013) */

#define LLQUEUE(name, size, type, cache_bytes)                                 \
	struct name                                                            \
	{                                                                      \
		atomic64_t front __attribute__((aligned(cache_bytes)));        \
		atomic64_t back __attribute__((aligned(cache_bytes)));         \
		type data[size];                                               \
	}

#define LLQUEUE_INIT(q)                                                        \
	{                                                                      \
		atomic64_set(&q->front, 0);                                    \
		atomic64_set(&q->back, 0);                                     \
	}

#define LLQUEUE_FULL(q, front, back) ((back + 1) % ARRAY_SIZE(q->data) == front)

#define LLQUEUE_EMPTY(q, front, back) (back == front)

#define LLQUEUE_PUSH(q, pfront, entry)                                         \
	({                                                                     \
		bool result = false;                                           \
		u64 back = atomic64_read(&q->back);                            \
		if (LLQUEUE_FULL(q, pfront, back)) {                           \
			pfront = atomic64_read(&q->front);                     \
		}                                                              \
		if (!LLQUEUE_FULL(q, pfront, back)) {                          \
			q->data[back] = entry;                                 \
			atomic64_set(&q->back,                                 \
				     (back + 1) % ARRAY_SIZE(q->data));        \
			result = true;                                         \
		}                                                              \
		result;                                                        \
	})

#define LLQUEUE_POP(q, cback, entry)                                           \
	({                                                                     \
		bool result = false;                                           \
		u64 front = atomic64_read(&q->front);                          \
		if (LLQUEUE_EMPTY(q, front, cback)) {                          \
			cback = atomic64_read(&q->back);                       \
		}                                                              \
		if (!LLQUEUE_EMPTY(q, front, cback)) {                         \
			entry = q->data[front];                                \
			atomic64_set(&q->front,                                \
				     (front + 1) % ARRAY_SIZE(q->data));       \
			result = true;                                         \
		}                                                              \
		result;                                                        \
	})

#endif /* LLQUEUE_H_ */
