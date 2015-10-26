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

#include <linux/mmu_context.h>

#include <hypercall_debug.h>
#include <hypercall_host.h>

static void vhost_handle_hypercall(struct vhost_work *work);

void hypercall_init_vq(struct hypercall_vq *hvq,
		       const struct hypercall *const *hcall, uint32_t hcall_num)
{
	hvq->vq.handle_kick = vhost_handle_hypercall;
	hvq->hypercall = hcall;
	hvq->hcall_num = hcall_num;
}

int hypercall_prepare_complete(struct hypercall_async *hcall_async)
{
	hcall_async->oldfs = get_fs();

	set_fs(USER_DS);
	if (hcall_async->hvq->vq.dev) {
		use_mm(hcall_async->hvq->vq.dev->mm);
		return 0;
	}

	return -ENODEV;
}

static void vhost_hypercall_complete_work(struct vhost_work *work)
{
	struct hypercall_async *hcall_async =
	    container_of(work, struct hypercall_async, work);
	struct vhost_virtqueue *vq = &hcall_async->hvq->vq;

	dprint(DBG_HOST, "\n");

	vhost_add_used(vq, hcall_async->head, 0);
	if (hcall_async->flags & HYPERCALL_SIGNAL_GUEST) {
		vhost_signal(vq->dev, vq);
	}
	kfree(hcall_async);
}

static void vhost_handle_hypercall(struct vhost_work *work)
{
	struct vhost_virtqueue *vq =
	    container_of(work, struct vhost_virtqueue, poll.work);
	struct hypercall_vq *hvq = container_of(vq, struct hypercall_vq, vq);
	struct vhost_dev *dev = vq->dev;
	unsigned int out, in;
	int head;

	dprint(DBG_HOST, "\n");

	vhost_disable_notify(dev, vq);

	for (;;) {
		int ret;
		struct iovec uhcall;
		struct hypercall_header hdr;
		struct hypercall_ret_header __user *hret;

		head = vhost_get_vq_desc(dev, vq, vq->iov, ARRAY_SIZE(vq->iov),
					 &out, &in, NULL, NULL);

		if (head < 0) {
			dprint(DBG_HOST, "no new desc\n");
			break;
		}

		if (vq->num == head) {
			if (vhost_enable_notify(dev, vq)) {
				vhost_disable_notify(dev, vq);
				continue;
			}
			break;
		}

		if (in == 0 || out == 0) {
			/* we shoud have at least 1 in and 1 out buffer
			 * responde to guest that there is something wrong with
			 * this command, if there is a out iov otherwise
			 * ignore!? */
			dprint(DBG_ON, "no in/out!\n");
			break;
		}

		hret =
		    (struct hypercall_ret_header __user *)vq->iov[out].iov_base;

		if (vq->iov[out].iov_len <
		    sizeof(struct hypercall_ret_header)) {
			dprint(DBG_ON, "response buffer to small\n");
			/* nothing we can do here */
			break;
		}

		uhcall = vq->iov[0];
		if (uhcall.iov_len < sizeof(struct hypercall_header)) {
			/* respond to guest that there is something wrong with
			 * this command */
			dprint(DBG_ON,
			       "hypercall header does not fit in buffer!\n");
			ret = -EINVAL;
			goto fail;
		}

		if (copy_from_user(&hdr, uhcall.iov_base, sizeof(hdr))) {
			dprint(DBG_ON,
			       "copy_from_user hypercall header failed!\n");
			ret = -EFAULT;
			goto fail;
		}

		dprint(DBG_HOST, "hypercall: %d\n", hdr.id);

		if (hdr.id >= hvq->hcall_num) {
			dprint(DBG_ON, "unknown hypercall id!\n");
			ret = -EINVAL;
			goto fail;
		}

		if (!hvq->hypercall[hdr.id]->func &&
		    !hvq->hypercall[hdr.id]->async_func) {
			dprint(DBG_ON, "hypercall not set!\n");
			ret = -EFAULT;
			goto fail;
		}

		if (hvq->hypercall[hdr.id]->npargs + 2 != out + in) {
			dprint(DBG_ON, "wrong number of arguments (%u/%u)\n",
			       hvq->hypercall[hdr.id]->npargs + 2, out + in);
			ret = -EINVAL;
			goto fail;
		}

		if (hvq->hypercall[hdr.id]->copy_arg_size != uhcall.iov_len) {
			dprint(DBG_ON,
			       "buffer size for copy arguments mismatch\n");
			ret = -EINVAL;
			goto fail;
		}

		if (hvq->hypercall[hdr.id]->return_size !=
		    vq->iov[out].iov_len) {
			dprint(DBG_ON, "return buffer to small\n");
			ret = -EINVAL;
			goto fail;
		}

		if (hdr.async) {

			dprint(DBG_HOST, "async hypercall\n");

			if (hvq->hypercall[hdr.id]->async_func) {
				struct hypercall_async *hcall_async;

				dprint(DBG_HOST, "has async function\n");

				hcall_async =
				    kmalloc(sizeof(*hcall_async), GFP_KERNEL);
				if (!hcall_async) {
					dprint(
					    DBG_ON,
					    "could not alloc hcall_async!\n");
					ret = -ENOMEM;
					goto fail;
				}
				vhost_work_init(&hcall_async->work,
						&vhost_hypercall_complete_work);
				hcall_async->hvq = hvq;
				hcall_async->head = head;
				hcall_async->flags = hdr.flags;
				hcall_async->hret = hret;
				ret = hvq->hypercall[hdr.id]
					  ->async_func(hcall_async, vq->iov);
				if (ret) {
					kfree(hcall_async);
				}
			} else {
				ret = -ENOSYS;
			}
		} else {

			dprint(DBG_HOST, "sync hypercall\n");

			if (hvq->hypercall[hdr.id]->func) {
				ret =
				    hvq->hypercall[hdr.id]->func(hvq, vq->iov);
			} else {
				ret = -ENOSYS;
			}
		}
	fail:
		if (ret || !hdr.async) {
			if (copy_to_user(hret, &ret, sizeof(*hret))) {
				dprint(DBG_ON, "copy to user failed!\n");
				break;
			}
			vhost_add_used(vq, head, 0);
			if (hdr.flags & HYPERCALL_SIGNAL_GUEST) {
				vhost_signal(dev, vq);
			}
		}
	}
}
