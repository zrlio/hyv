/*
 * Object map
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

#include <linux/slab.h>
#include <linux/compiler.h>

#include <stddef.h>

#include "object_map_debug.h"

#include "object_map.h"

void object_map_init(struct object_map *map)
{
	idr_init(&map->idr);
	spin_lock_init(&map->lock);
}

void object_map_destroy(struct object_map *map,
			void (*release)(struct object *obj), bool force)
{
	unsigned long flags;
	struct object *obj;
	u32 id;

	spin_lock_irqsave(&map->lock, flags);
	idr_for_each_entry(&map->idr, obj, id)
	{
		bool released = object_put(obj, release);
		if (!released && force) {
			dprint(DBG_ON, "force release (%d)\n", obj->id);
			release(obj);
			released = true;
		}
		if (released) {
			/* if the object was released we need to remove it from
			 * its parent */
			if (!list_empty(&obj->list)) {
				list_del(&obj->list);
			}
		}
	}
	idr_destroy(&map->idr);
	spin_unlock_irqrestore(&map->lock, flags);
}

/* do not add objects twice! */
int object_map_add(struct object_map *map, struct list_head *head,
		   struct object *obj)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&map->lock, flags);
	ret = idr_alloc(&map->idr, obj, 0, 0, GFP_KERNEL);
	if (ret >= 0) {
		obj->id = ret;
		obj->map = map;
		kref_init(&obj->ref_cnt);
		if (head) {
			list_add(&obj->list, head);
		} else {
			INIT_LIST_HEAD(&obj->list);
		}
	} else {
		dprint(DBG_ON, "adding user object failed!\n");
	}
	spin_unlock_irqrestore(&map->lock, flags);

	return ret;
}

struct object *object_map_id_get(struct object_map *map, uint32_t id)
{
	struct object *obj;
	unsigned long flags;

	spin_lock_irqsave(&map->lock, flags);
	obj = idr_find(&map->idr, id);
	if (obj) {
		object_get(obj);
	}
	spin_unlock_irqrestore(&map->lock, flags);

	return obj;
}

int object_map_id_del(struct object_map *map, uint32_t id,
		      void (*release)(struct object *obj))
{
	struct object *obj;

	obj = object_map_id_get(map, id);
	if (!obj) {
		dprint(DBG_ON, "no obj with this id!\n");
		return -EINVAL;
	}
	BUG_ON(object_put(obj, release));
	object_map_del(obj, release);

	return 0;
}

int object_map_del(struct object *obj, void (*release)(struct object *obj))
{
	struct object_map *map = obj->map;
	unsigned long flags;

	spin_lock_irqsave(&map->lock, flags);
	if (!list_empty(&obj->list)) {
		list_del(&obj->list);
	}
	idr_remove(&map->idr, obj->id);
	spin_unlock_irqrestore(&map->lock, flags);

	return object_put(obj, release);
}

void object_get(struct object *obj)
{
	kref_get(&obj->ref_cnt);
}

int object_put(struct object *obj, void (*release)(struct object *obj))
{
	compiletime_assert(offsetof(struct object, ref_cnt) == 0,
			   "ref_cnt must be first member (callback)");
	return kref_put(&obj->ref_cnt, (void (*)(struct kref *))release);
}
