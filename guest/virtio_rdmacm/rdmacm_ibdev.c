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

#include "virtio_rdmacm_debug.h"

#include "rdmacm_ibdev.h"

static struct
{
	struct list_head head;
	spinlock_t lock;
} rdmacm_ibdev_list;

struct rdmacm_ibdev
{
	struct ib_device *dev;
	struct kref ref_cnt;
	struct completion completion;
	struct list_head list;
};

static void rdmacm_add_ibdev(struct ib_device *ibdev);
static void rdmacm_remove_ibdev(struct ib_device *ibdev);

struct ib_client rdmacm_ib_client = { .name = "rdmacm",
				      .add = rdmacm_add_ibdev,
				      .remove = rdmacm_remove_ibdev };

struct ib_device *rdmacm_get_ibdev(__be64 node_guid)
{
	struct rdmacm_ibdev *e;
	bool found = false;

	spin_lock(&rdmacm_ibdev_list.lock);
	list_for_each_entry(e, &rdmacm_ibdev_list.head, list)
	{
		if (e->dev->node_guid == node_guid) {
			found = true;
			break;
		}
	}
	if (found) {
		kref_get(&e->ref_cnt);
	}
	spin_unlock(&rdmacm_ibdev_list.lock);

	if (found) {
		return e->dev;
	} else {
		return NULL;
	}
}

static void rdmacm_ibdev_release(struct kref *kref)
{
	struct rdmacm_ibdev *gibdev =
	    container_of(kref, struct rdmacm_ibdev, ref_cnt);

	complete(&gibdev->completion);
}

void rdmacm_put_ibdev(struct ib_device *ibdev)
{
	struct rdmacm_ibdev *gibdev;

	gibdev = ib_get_client_data(ibdev, &rdmacm_ib_client);
	if (!gibdev) {
		dprint(DBG_ON, "no client data\n");
		return;
	}
	kref_put(&gibdev->ref_cnt, &rdmacm_ibdev_release);
}

static void rdmacm_add_ibdev(struct ib_device *ibdev)
{
	struct rdmacm_ibdev *gibdev;

	dprint(DBG_IBCLIENT, "%s\n", ibdev->name);

	gibdev = kmalloc(sizeof(*gibdev), GFP_KERNEL);
	if (!gibdev) {
		dprint(DBG_ON, "allocating ibdev failed!\n");
		module_put(ibdev->owner);
		return;
	}
	gibdev->dev = ibdev;
	kref_init(&gibdev->ref_cnt);
	init_completion(&gibdev->completion);

	ib_set_client_data(ibdev, &rdmacm_ib_client, gibdev);

	spin_lock(&rdmacm_ibdev_list.lock);
	list_add_tail(&gibdev->list, &rdmacm_ibdev_list.head);
	spin_unlock(&rdmacm_ibdev_list.lock);
}

static void rdmacm_remove_ibdev(struct ib_device *ibdev)
{
	struct rdmacm_ibdev *gibdev;

	dprint(DBG_IBCLIENT, "%s\n", ibdev->name);

	gibdev = ib_get_client_data(ibdev, &rdmacm_ib_client);
	if (!gibdev) {
		dprint(DBG_ON, "no client data\n");
		return;
	}

	spin_lock(&rdmacm_ibdev_list.lock);
	list_del(&gibdev->list);
	spin_unlock(&rdmacm_ibdev_list.lock);

	if (kref_put(&gibdev->ref_cnt, &rdmacm_ibdev_release) != 1) {
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

void rdmacm_exit_ibdev(void)
{
	/* removes all devices added to this client */
	ib_unregister_client(&rdmacm_ib_client);
}

int rdmacm_init_ibdev(void)
{
	INIT_LIST_HEAD(&rdmacm_ibdev_list.head);
	spin_lock_init(&rdmacm_ibdev_list.lock);
	return ib_register_client(&rdmacm_ib_client);
}
