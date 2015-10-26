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

#include <hypercall_host.h>
#include <hyv_hypercall.h>

#include <virtio_hyv_config.h>

#include "vhost_hyv_ibdev.h"
#include "vhost_hyv_dev.h"
#include "vhost_hyv_mem.h"
#include "vhost_hyv_event.h"

#include "vhost_hyv.h"
#include "vhost_hyv_debug.h"

#define VHOST_HYV_MINOR 239
#define VHOST_HYV_MMAP_MINOR 240

static DEVICE_ATTR(add, S_IWUGO, NULL, vhost_hyv_add_device);

static const struct hypercall *const hcall[] =
    {[VIRTIO_HYV_GET_IB_DEV] = &hypercall_hyv_get_ib_device,
     [VIRTIO_HYV_PUT_IB_DEV] = &hypercall_hyv_put_ib_device,
     [VIRTIO_HYV_MMAP] = &hypercall_hyv_mmap,
     [VIRTIO_HYV_MUNMAP] = &hypercall_hyv_munmap,
     [VIRTIO_HYV_IBV_QUERY_DEV] = &hypercall_hyv_ibv_query_deviceX,
     [VIRTIO_HYV_IBV_QUERY_PORT] = &hypercall_hyv_ibv_query_portX,
     [VIRTIO_HYV_IBV_QUERY_PKEY] = &hypercall_hyv_ibv_query_pkeyX,
     [VIRTIO_HYV_IBV_QUERY_GID] = &hypercall_hyv_ibv_query_gidX,
     [VIRTIO_HYV_IBV_ALLOC_UCTX] = &hypercall_hyv_ibv_alloc_ucontextX,
     [VIRTIO_HYV_IBV_DEALLOC_UCTX] = &hypercall_hyv_ibv_dealloc_ucontextX,
     [VIRTIO_HYV_IBV_ALLOC_PD] = &hypercall_hyv_ibv_alloc_pdX,
     [VIRTIO_HYV_IBV_DEALLOC_PD] = &hypercall_hyv_ibv_dealloc_pdX,
     [VIRTIO_HYV_IBV_CREATE_CQ] = &hypercall_hyv_ibv_create_cqX,
     [VIRTIO_HYV_IBV_DESTROY_CQ] = &hypercall_hyv_ibv_destroy_cqX,
     [VIRTIO_HYV_IBV_CREATE_QP] = &hypercall_hyv_ibv_create_qpX,
     [VIRTIO_HYV_IBV_MODIFY_QP] = &hypercall_hyv_ibv_modify_qpX,
     [VIRTIO_HYV_IBV_QUERY_QP] = &hypercall_hyv_ibv_query_qpX,
     [VIRTIO_HYV_IBV_DESTROY_QP] = &hypercall_hyv_ibv_destroy_qpX,
     [VIRTIO_HYV_IBV_CREATE_SRQ] = &hypercall_hyv_ibv_create_srqX,
     [VIRTIO_HYV_IBV_MODIFY_SRQ] = &hypercall_hyv_ibv_modify_srqX,
     [VIRTIO_HYV_IBV_DESTROY_SRQ] = &hypercall_hyv_ibv_destroy_srqX,
     [VIRTIO_HYV_IBV_REG_USER_MR] = &hypercall_hyv_ibv_reg_user_mrX,
     [VIRTIO_HYV_IBV_DEREG_MR] = &hypercall_hyv_ibv_dereg_mrX,
     [VIRTIO_HYV_IBV_POST_SEND_NULL] = &hypercall_hyv_ibv_post_send_nullX, };

struct class *hyv_class;

static void vhost_hyv_vg_release(struct device *dev)
{
	/* nothing to do here! */
}

static int vhost_hyv_open(struct inode *inode, struct file *f)
{
	struct vhost_hyv *vg;
	struct vhost_virtqueue **vqs;
	int ret;

	dprint(DBG_VHOST, "\n");

	vg = kzalloc(sizeof(*vg), GFP_KERNEL);
	if (!vg) {
		dprint(DBG_ON, "could not alloc vhost hyv\n");
		ret = -ENOMEM;
		goto fail;
	}
	spin_lock_init(&vg->evt_lock);
	object_map_init(&vg->devices);
	object_map_init(&vg->uctxs);
	object_map_init(&vg->pds);
	object_map_init(&vg->cqs);
	object_map_init(&vg->qps);
	object_map_init(&vg->srqs);
	object_map_init(&vg->mrs);
	object_map_init(&vg->mmaps);

	vg->dev.class = hyv_class;
	vg->dev.release = &vhost_hyv_vg_release;
	dev_set_name(&vg->dev, "vhost-%d", current->pid);
	ret = device_register(&vg->dev);
	if (ret) {
		dprint(DBG_ON, "could not register device\n");
		goto fail_vg;
	}

	dev_set_drvdata(&vg->dev, vg);

	ret = device_create_file(&vg->dev, &dev_attr_add);
	if (ret) {
		dprint(DBG_ON, "could not create file\n");
		goto fail_devreg;
	}

	vqs = kmalloc(VIRTIO_HYV_NVQS * sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		dprint(DBG_ON, "could not alloc vqs\n");
		ret = -ENOMEM;
		goto fail_devreg;
	}

	vqs[VIRTIO_HYV_VQ_HCALL] = &vg->vq_hcall.vq;
	vqs[VIRTIO_HYV_VQ_EVT] = &vg->vq_evt;

	hypercall_init_vq(&vg->vq_hcall, hcall, VIRTIO_HYV_NHCALLS);
	vqs[VIRTIO_HYV_VQ_EVT]->handle_kick = vhost_hyv_handle_evt;

	vhost_dev_init(&vg->vdev, vqs, VIRTIO_HYV_NVQS);
	f->private_data = vg;
	return 0;
fail_devreg:
	device_unregister(&vg->dev);
fail_vg:
	kfree(vg);
fail:
	return ret;
}

static void vhost_hyv_flush(struct vhost_hyv *vg)
{
	dprint(DBG_VHOST, "\n");

	vhost_poll_flush(&vg->vq_hcall.vq.poll);
	vhost_poll_flush(&vg->vq_evt.poll);
}

static int vhost_hyv_release(struct inode *inode, struct file *f)
{
	struct vhost_hyv *vg = f->private_data;

	dprint(DBG_VHOST, "\n");

	vhost_hyv_flush(vg);
	vhost_dev_stop(&vg->vdev);
	vhost_dev_cleanup(&vg->vdev, false);

	/* Make sure no callbacks are outstanding */
	synchronize_rcu_bh();
	/* We do an extra flush before freeing memory,
	* since jobs can re-queue themselves. */
	vhost_hyv_flush(vg);

	vhost_hyv_event_cleanup(vg);

	/* these object build a dependency tree
	 * so we let their parents force release them eventually
	 * (except devices they do not have any parents) */
	object_map_destroy(&vg->mmaps, &vhost_hyv_mmap_release, false);
	object_map_destroy(&vg->mrs, &vhost_hyv_mr_release, false);
	object_map_destroy(&vg->srqs, &vhost_hyv_srq_release, false);
	object_map_destroy(&vg->qps, &vhost_hyv_qp_release, false);
	object_map_destroy(&vg->cqs, &vhost_hyv_cq_release, false);
	object_map_destroy(&vg->pds, &vhost_hyv_pd_release, false);
	object_map_destroy(&vg->uctxs, &vhost_hyv_ucontext_release, false);
	object_map_destroy(&vg->devices, &vhost_hyv_device_release, true);

	device_unregister(&vg->dev);

	kfree(vg->vdev.vqs);
	kfree(vg);
	return 0;
}

static long vhost_hyv_reset_owner(struct vhost_hyv *vg)
{
	long err;
	struct vhost_memory *memory;

	dprint(DBG_VHOST, "\n");

	mutex_lock(&vg->vdev.mutex);
	err = vhost_dev_check_owner(&vg->vdev);
	if (err) {
		goto done;
	}

	memory = vhost_dev_reset_owner_prepare();
	if (!memory) {
		err = -ENOMEM;
		goto done;
	}

	// vhost_hyv_stop(vg);
	vhost_hyv_flush(vg);
	vhost_dev_reset_owner(&vg->vdev, memory);
done:
	mutex_unlock(&vg->vdev.mutex);
	return err;
}

static int vhost_hyv_set_features(struct vhost_hyv *vg, u64 features)
{
	dprint(DBG_VHOST, "\n");

	mutex_lock(&vg->vdev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&vg->vdev)) {
		mutex_unlock(&vg->vdev.mutex);
		return -EFAULT;
	}
	vg->vdev.acked_features = features;
	mutex_unlock(&vg->vdev.mutex);
	return 0;
}

static long vhost_hyv_set_owner(struct vhost_hyv *vg)
{
	int ret;

	dprint(DBG_VHOST, "\n");

	mutex_lock(&vg->vdev.mutex);
	if (vhost_dev_has_owner(&vg->vdev)) {
		ret = -EBUSY;
		goto out;
	}

	ret = vhost_dev_set_owner(&vg->vdev);
	vhost_hyv_flush(vg);
out:
	mutex_unlock(&vg->vdev.mutex);
	return ret;
}

static long vhost_hyv_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
	struct vhost_hyv *vg = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int ret;

	dprint(DBG_VHOST, "%x\n", ioctl);

	switch (ioctl) {
	case VHOST_HYV_ADD_DEVS: {
		struct vhost_hyv_device *gdev;
		u32 id;

		BUG_ON(!vg->evt_queue);

		/* this should only be called once! */
		object_map_for_each_entry(&vg->devices, gdev, id)
		{
			struct hyv_event event = { .type = HYV_EVENT_ADD_DEVICE,
						   .id = id, };
			vhost_hyv_push_event(vg, event, false);
		}
		vhost_hyv_signal_event(vg);
		return 0;
	}
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
		return vhost_hyv_set_features(vg, features);
	case VHOST_RESET_OWNER:
		return vhost_hyv_reset_owner(vg);
	case VHOST_SET_OWNER:
		return vhost_hyv_set_owner(vg);
	default:
		mutex_lock(&vg->vdev.mutex);
		ret = vhost_dev_ioctl(&vg->vdev, ioctl, argp);
		if (ret == -ENOIOCTLCMD) {
			ret = vhost_vring_ioctl(&vg->vdev, ioctl, argp);
		} else {
			vhost_hyv_flush(vg);
		}
		mutex_unlock(&vg->vdev.mutex);
		return ret;
	}
}

#ifdef CONFIG_COMPAT
static long vhost_hyv_compat_ioctl(struct file *f, unsigned int ioctl,
				   unsigned long arg)
{
	return vhost_hyv_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vhost_hyv_fops = {
	.owner = THIS_MODULE,
	.release = vhost_hyv_release,
	.unlocked_ioctl = vhost_hyv_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = vhost_hyv_compat_ioctl,
#endif
	.open = vhost_hyv_open,
	.llseek = noop_llseek,
};

static struct miscdevice vhost_hyv_misc = { .minor = VHOST_HYV_MINOR,
					    .name = "vhost-hyv",
					    .fops = &vhost_hyv_fops, };

static int vhost_hyv_mmap_file_release(struct inode *inode, struct file *f)
{
	return 0;
}

const static struct file_operations vhost_hyv_mmap_ops = {
	.owner = THIS_MODULE,
	.mmap = vhost_hyv_mmap_wrapper,
	.release = vhost_hyv_mmap_file_release,
};

static struct miscdevice vhost_hyv_mmap_misc = { .minor = VHOST_HYV_MMAP_MINOR,
						 .name = "vhost-hyv-mmap",
						 .fops = &vhost_hyv_mmap_ops, };

static int vhost_hyv_init(void)
{
	int ret;

	dprint(DBG_ON, "\n");

	hyv_class = class_create(THIS_MODULE, "hyv");
	if (IS_ERR(hyv_class)) {
		dprint(DBG_ON, "could not create class\n");
		ret = PTR_ERR(hyv_class);
		goto fail;
	}

	ret = vhost_hyv_init_ibdev();
	if (ret) {
		dprint(DBG_ON, "could not init ibdev\n");
		goto fail_class;
	}

	ret = vhost_mem_init();
	if (ret) {
		dprint(DBG_ON, "could not init mem\n");
		goto fail_ibdev;
	}

	ret = misc_register(&vhost_hyv_mmap_misc);
	if (ret) {
		dprint(DBG_ON, "could not init mmap misc\n");
		goto fail_mem;
	}

	ret = misc_register(&vhost_hyv_misc);
	if (ret) {
		dprint(DBG_ON, "could not init misc\n");
		goto fail_mmap_misc;
	}

#if DBG_HCALL &DPRINT_MASK
	{
		uint32_t i;
		dprint(DBG_ON, "hypercalls: \n");
		for (i = 0; i < ARRAY_SIZE(hcall); i++) {
			dprint(DBG_ON,
			       "%d { .func = %p, .npargs = %u, "
			       ".copy_arg_size = %u, .return_size = %u}\n",
			       i, hcall[i]->func, hcall[i]->npargs,
			       hcall[i]->copy_arg_size, hcall[i]->return_size);
		}
	}
#endif

	return 0;
fail_mmap_misc:
	misc_deregister(&vhost_hyv_mmap_misc);
fail_mem:
	vhost_mem_exit();
fail_ibdev:
	vhost_hyv_exit_ibdev();
fail_class:
	class_destroy(hyv_class);
fail:
	return ret;
}
module_init(vhost_hyv_init);

static void vhost_hyv_exit(void)
{
	dprint(DBG_ON, "\n");
	vhost_hyv_exit_ibdev();
	misc_deregister(&vhost_hyv_misc);
	misc_deregister(&vhost_hyv_mmap_misc);
	class_destroy(hyv_class);
	vhost_mem_exit();
}
module_exit(vhost_hyv_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jonas Pfefferle");
MODULE_DESCRIPTION("Host kernel accelerator for virtio hyv");
MODULE_ALIAS_MISCDEV(VHOST_HYV_MINOR);
MODULE_ALIAS("devname:vhost-hyv");
