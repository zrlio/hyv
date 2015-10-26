/*
 * hybrid virtualization (hyv) for linux
 *
 * author: jonas pfefferle <jpf@zurich.ibm.com>
 *
 * copyright (c) 2015, ibm corporation
 *
 * this program is free software; you can redistribute it and/or
 * modify it under the terms of the gnu general public license version 2
 * as published by the free software foundation.
 *
 * this program is distributed in the hope that it will be useful,
 * but without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the
 * gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license
 * along with this program; if not, write to the free software
 * foundation, inc., 51 franklin street, fifth floor, boston, ma  02110-1301,
 *usa.
 */

#ifndef VHOST_HYV_MEM_H_
#define VHOST_HYV_MEM_H_

#include <virthyv.h>

struct vhost_hyv_file;

int vhost_hyv_cmd_ib_mmap(struct vhost_hyv *vhyv,
			  struct virthyv_cmd_ib_mmap __user *ucmd,
			  unsigned long size,
			  struct virthyv_resp_ib_mmap __user *uresp);

int vhost_hyv_cmd_ib_unmap(struct vhost_hyv *vhyv,
			   struct virthyv_cmd_ib_unmap __user *ucmd);

void vhost_hyv_ib_unmap_all(struct vhost_hyv_file *file, int release);

int vhost_hyv_cmd_mmap(struct vhost_hyv *vhyv,
		       struct virthyv_cmd_mmap __user *ucmd, unsigned long size,
		       struct virthyv_resp_mmap __user *uresp);

int vhost_hyv_cmd_unmap(struct vhost_hyv *vhyv,
			struct virthyv_cmd_unmap __user *ucmd);

#endif /* VHOST_HYV_MEM_H_ */
