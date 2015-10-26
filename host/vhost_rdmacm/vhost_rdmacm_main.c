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

#include <linux/compat.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/virtio.h>

#define VHOST_RDMACM_MINOR 241

#include <hypercall_host.h>
#include <rdmacm_hypercall.h>

#include <virtio_rdmacm_config.h>

#include "vhost_rdmacm_debug.h"

#include "vhost_rdmacm.h"

static const struct hypercall *const hcall[] =
    {[VIRTIO_RDMACM_POST_EVENT] = &hypercall_vrdmacm_post_event,
     [VIRTIO_RDMACM_CREATE_ID] = &hypercall_vrdmacm_create_id,
     [VIRTIO_RDMACM_DESTROY_ID] = &hypercall_vrdmacm_destroy_id,
     [VIRTIO_RDMACM_RESOLVE_ADDR] = &hypercall_vrdmacm_resolve_addr,
     [VIRTIO_RDMACM_RESOLVE_ROUTE] = &hypercall_vrdmacm_resolve_route,
     [VIRTIO_RDMACM_CONNECT] = &hypercall_vrdmacm_connect, };

static int vhost_rdmacm_open(struct inode *inode, struct file *f)
{
	struct vhost_rdmacm *vcm;
	struct vhost_virtqueue **vqs;
	int ret;

	dprint(DBG_VHOST, "\n");

	vcm = kzalloc(sizeof(*vcm), GFP_KERNEL);
	if (!vcm) {
		dprint(DBG_ON, "could not alloc vhost\n");
		ret = -ENOMEM;
		goto fail;
	}

	object_map_init(&vcm->ctxs);

	vqs = kmalloc(sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		dprint(DBG_ON, "could not alloc vqs\n");
		ret = -ENOMEM;
		goto fail_vcm;
	}

	*vqs = &vcm->vq.vq;

	hypercall_init_vq(&vcm->vq, hcall, VIRTIO_RDMACM_NHCALLS);

	vhost_dev_init(&vcm->vdev, vqs, 1);
	f->private_data = vcm;
	return 0;
fail_vcm:
	kfree(vcm);
fail:
	return ret;
}

static void vhost_rdmacm_flush(struct vhost_rdmacm *vcm)
{
	dprint(DBG_VHOST, "\n");

	vhost_poll_flush(&vcm->vq.vq.poll);
}

static int vhost_rdmacm_release(struct inode *inode, struct file *f)
{
	struct vhost_rdmacm *vcm = f->private_data;

	dprint(DBG_VHOST, "\n");

	vhost_rdmacm_flush(vcm);
	vhost_dev_stop(&vcm->vdev);
	vhost_dev_cleanup(&vcm->vdev, false);

	object_map_destroy(&vcm->ctxs, &vhost_rdmacm_ctx_release, true);

	/* Make sure no callbacks are outstanding */
	synchronize_rcu_bh();
	/* We do an extra flush before freeing memory,
	* since jobs can re-queue themselves. */
	vhost_rdmacm_flush(vcm);

	kfree(vcm->vdev.vqs);
	kfree(vcm);
	return 0;
}

static long vhost_rdmacm_reset_owner(struct vhost_rdmacm *vcm)
{
	long err;
	struct vhost_memory *memory;

	dprint(DBG_VHOST, "\n");

	mutex_lock(&vcm->vdev.mutex);
	err = vhost_dev_check_owner(&vcm->vdev);
	if (err) {
		goto done;
	}

	memory = vhost_dev_reset_owner_prepare();
	if (!memory) {
		err = -ENOMEM;
		goto done;
	}

	vhost_rdmacm_flush(vcm);
	vhost_dev_reset_owner(&vcm->vdev, memory);
done:
	mutex_unlock(&vcm->vdev.mutex);
	return err;
}

static int vhost_rdmacm_set_features(struct vhost_rdmacm *vcm, u64 features)
{
	dprint(DBG_VHOST, "\n");

	mutex_lock(&vcm->vdev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&vcm->vdev)) {
		mutex_unlock(&vcm->vdev.mutex);
		return -EFAULT;
	}
	vcm->vdev.acked_features = features;
	mutex_unlock(&vcm->vdev.mutex);
	return 0;
}

static long vhost_rdmacm_set_owner(struct vhost_rdmacm *vcm)
{
	int ret;

	dprint(DBG_VHOST, "\n");

	mutex_lock(&vcm->vdev.mutex);
	if (vhost_dev_has_owner(&vcm->vdev)) {
		ret = -EBUSY;
		goto out;
	}

	ret = vhost_dev_set_owner(&vcm->vdev);
	vhost_rdmacm_flush(vcm);
out:
	mutex_unlock(&vcm->vdev.mutex);
	return ret;
}

static long vhost_rdmacm_ioctl(struct file *f, unsigned int ioctl,
			       unsigned long arg)
{
	struct vhost_rdmacm *vcm = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int ret;

	dprint(DBG_VHOST, "%x\n", ioctl);

	switch (ioctl) {
	case VHOST_GET_FEATURES:
		features = (1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) |
			   (1ULL << VIRTIO_RING_F_EVENT_IDX) |
			   (1ULL << VHOST_F_LOG_ALL);
		if (copy_to_user(featurep, &features, sizeof features)) {
			return -EFAULT;
		}
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, featurep, sizeof features)) {
			return -EFAULT;
		}
		return vhost_rdmacm_set_features(vcm, features);
	case VHOST_RESET_OWNER:
		return vhost_rdmacm_reset_owner(vcm);
	case VHOST_SET_OWNER:
		return vhost_rdmacm_set_owner(vcm);
	default:
		mutex_lock(&vcm->vdev.mutex);
		ret = vhost_dev_ioctl(&vcm->vdev, ioctl, argp);
		if (ret == -ENOIOCTLCMD) {
			ret = vhost_vring_ioctl(&vcm->vdev, ioctl, argp);
		} else {
			vhost_rdmacm_flush(vcm);
		}
		mutex_unlock(&vcm->vdev.mutex);
		return ret;
	}
}

#ifdef CONFIG_COMPAT
static long vhost_rdmacm_compat_ioctl(struct file *f, unsigned int ioctl,
				      unsigned long arg)
{
	return vhost_rdmacm_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vhost_rdmacm_fops = {
	.owner = THIS_MODULE,
	.release = vhost_rdmacm_release,
	.unlocked_ioctl = vhost_rdmacm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = vhost_rdmacm_compat_ioctl,
#endif
	.open = vhost_rdmacm_open,
	.llseek = noop_llseek,
};

static struct miscdevice vhost_rdmacm_misc = { .minor = VHOST_RDMACM_MINOR,
					       .name = "vhost-rdmacm",
					       .fops = &vhost_rdmacm_fops, };

static int vhost_rdmacm_init(void)
{
	int ret;

	dprint(DBG_ON, "\n");

	ret = misc_register(&vhost_rdmacm_misc);
	if (ret) {
		dprint(DBG_ON, "could not init misc\n");
	}

	return ret;
}
module_init(vhost_rdmacm_init);

static void vhost_rdmacm_exit(void)
{
	dprint(DBG_ON, "\n");
	misc_deregister(&vhost_rdmacm_misc);
}
module_exit(vhost_rdmacm_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jonas Pfefferle");
MODULE_DESCRIPTION("Host kernel accelerator for virtio rdmacm");
MODULE_ALIAS_MISCDEV(VHOST_RDMACM_MINOR);
MODULE_ALIAS("devname:vhost-rdmacm");
