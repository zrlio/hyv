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

#ifndef RDMACM_IBDEV_H_
#define RDMACM_IBDEV_H_

#include <rdma/ib_user_verbs.h>

struct ib_device *rdmacm_get_ibdev(__be64 node_guid);
void rdmacm_put_ibdev(struct ib_device *ibdev);

int rdmacm_init_ibdev(void);
void rdmacm_exit_ibdev(void);

#endif /* RDMACM_IBDEV_H_ */
