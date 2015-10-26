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

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/kref.h>

#include <rdma/ib_verbs.h>

#include "vhost_hyv_debug.h"

#include "vhost_hyv_ibdev.h"

static struct
{
	struct list_head head;
	spinlock_t lock;
} vhost_hyv_ibdev_list;

struct vhost_hyv_ibdev
{
	struct ib_device *dev;
	struct kref ref_cnt;
	struct completion completion;
	struct list_head list;
};

static void vhost_hyv_add_ibdev(struct ib_device *ibdev);
static void vhost_hyv_remove_ibdev(struct ib_device *ibdev);

struct ib_client vhost_hyv_ib_client = { .name = "vhost_hyv",
					 .add = vhost_hyv_add_ibdev,
					 .remove = vhost_hyv_remove_ibdev };

struct ib_device *vhost_hyv_get_ibdev(__be64 node_guid)
{
	struct vhost_hyv_ibdev *e;
	bool found = false;

	spin_lock(&vhost_hyv_ibdev_list.lock);
	list_for_each_entry(e, &vhost_hyv_ibdev_list.head, list)
	{
		if (e->dev->node_guid == node_guid) {
			found = true;
			break;
		}
	}
	if (found) {
		kref_get(&e->ref_cnt);
	}
	spin_unlock(&vhost_hyv_ibdev_list.lock);

	if (found) {
		return e->dev;
	} else {
		return NULL;
	}
}

static void vhost_hyv_ibdev_release(struct kref *kref)
{
	struct vhost_hyv_ibdev *gibdev =
	    container_of(kref, struct vhost_hyv_ibdev, ref_cnt);

	complete(&gibdev->completion);
}

void vhost_hyv_put_ibdev(struct ib_device *ibdev)
{
	struct vhost_hyv_ibdev *gibdev;

	gibdev = ib_get_client_data(ibdev, &vhost_hyv_ib_client);
	if (!gibdev) {
		dprint(DBG_ON, "no client data\n");
		return;
	}
	kref_put(&gibdev->ref_cnt, &vhost_hyv_ibdev_release);
}

static void vhost_hyv_add_ibdev(struct ib_device *ibdev)
{
	struct vhost_hyv_ibdev *gibdev;
	struct module *mod = THIS_MODULE;
	struct module_use *use;
	bool uses = false;

	dprint(DBG_IBCLIENT, "%s\n", ibdev->name);

	list_for_each_entry(use, &mod->source_list, source_list)
	{
		if (use->source == ibdev->owner) {
			uses = true;
			break;
		}
	}

	if (!uses) {
		dprint(DBG_ON, "Could not add ibdev (%llx) -> reload module\n",
		       ibdev->node_guid);
		return;
	}

	gibdev = kmalloc(sizeof(*gibdev), GFP_KERNEL);
	if (!gibdev) {
		dprint(DBG_ON, "allocating ibdev failed!\n");
		module_put(ibdev->owner);
		return;
	}
	gibdev->dev = ibdev;
	kref_init(&gibdev->ref_cnt);
	init_completion(&gibdev->completion);

	ib_set_client_data(ibdev, &vhost_hyv_ib_client, gibdev);

	spin_lock(&vhost_hyv_ibdev_list.lock);
	list_add_tail(&gibdev->list, &vhost_hyv_ibdev_list.head);
	spin_unlock(&vhost_hyv_ibdev_list.lock);
}

static void vhost_hyv_remove_ibdev(struct ib_device *ibdev)
{
	struct vhost_hyv_ibdev *gibdev;

	dprint(DBG_IBCLIENT, "%s\n", ibdev->name);

	gibdev = ib_get_client_data(ibdev, &vhost_hyv_ib_client);
	if (!gibdev) {
		dprint(DBG_ON, "no client data\n");
		return;
	}

	spin_lock(&vhost_hyv_ibdev_list.lock);
	list_del(&gibdev->list);
	spin_unlock(&vhost_hyv_ibdev_list.lock);

	if (kref_put(&gibdev->ref_cnt, &vhost_hyv_ibdev_release) != 1) {
		dprint(DBG_ON, "ibdev (%llx) is in use\n", ibdev->node_guid);
		while (!wait_for_completion_timeout(
			    &gibdev->completion, msecs_to_jiffies(30 * 1000))) {
			dprint(DBG_ON, "ibdev (%llx) is still in use..."
				       "waiting!\n",
			       ibdev->node_guid);
		}
	}
	kfree(gibdev);
}

void vhost_hyv_exit_ibdev(void)
{
	/* removes all devices added to this client */
	ib_unregister_client(&vhost_hyv_ib_client);
}

int vhost_hyv_init_ibdev(void)
{
	INIT_LIST_HEAD(&vhost_hyv_ibdev_list.head);
	spin_lock_init(&vhost_hyv_ibdev_list.lock);
	return ib_register_client(&vhost_hyv_ib_client);
}
