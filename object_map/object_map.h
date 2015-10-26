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

#ifndef OBJECT_MAP_H_
#define OBJECT_MAP_H_

#include <linux/types.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/compiler.h>

struct object_map
{
	struct idr idr;
	spinlock_t lock;
};

struct object
{
	struct kref ref_cnt;
	/* we have a global map mostly for fast lookup, however we
	 * need a local dependency list for clean up */
	struct list_head list;
	struct object_map *map;
	uint32_t id;
};

void object_map_init(struct object_map *map);
void object_map_destroy(struct object_map *map,
			void (*release)(struct object *obj), bool force);

/* operations on object map */

int object_map_add(struct object_map *map, struct list_head *head,
		   struct object *obj);

struct object *object_map_id_get(struct object_map *map, uint32_t id);

int object_map_id_del(struct object_map *map, uint32_t id,
		      void (*release)(struct object *obj));

int object_map_del(struct object *obj, void (*release)(struct object *obj));

/* operation on object */

void object_get(struct object *obj);

int object_put(struct object *obj, void (*release)(struct object *obj));

#define object_map_id_get_entry(map, type, field, id)                          \
	({                                                                     \
		struct object *__obj = object_map_id_get(map, id);             \
		__obj ? container_of(__obj, type, field) : NULL;               \
	})

#define object_map_for_each_entry(map, entry, id)                              \
	idr_for_each_entry(&(map)->idr, entry, id)

#endif /* OBJECT_MAP_H_ */
