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

#ifndef HYV_EVENT_H_
#define HYV_EVENT_H_

#include <llqueue.h>
#include <linux/stddef.h>

/* this covers all events in verbs:
 * - completions
 * - srq/cq/qp events
 * Additionally:
 * - adding/removing devices */

enum hyv_event_type {
	HYV_EVENT_CQ_COMP = 0,
	HYV_EVENT_CQ,
	HYV_EVENT_QP,
	HYV_EVENT_SRQ,
	HYV_EVENT_ASYNC, /* global events like port failure */
	HYV_EVENT_ADD_DEVICE,
	HYV_EVENT_REM_DEVICE
};

/* We might want to cache align the events */
struct hyv_event
{
	__u16 type; /* event type */
	__u8 port;
	__u32 ibevent; /* ib event type */
	__u64 id;      /* cq/qp/srq or device id*/
};

/* FIXME: size is limit of what we can kmap in one page (on host) */
/* cache line size should be max of guest and host sizes */
LLQUEUE(hyv_event_queue, 128, struct hyv_event, 64);

#endif /* HYV_EVENT_H_ */
