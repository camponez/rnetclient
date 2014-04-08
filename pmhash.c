/*
 *  Copyright (C) 2012-2013  Thadeu Lima de Souza Cascardo <cascardo@minaslivre.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "pmhash.h"
#include <stdlib.h>
#include <string.h>

struct item {
	char *key;
	void *val;
};

struct pmhash {
	size_t len;
	struct item items[];
};

struct pmhash * pmhash_new(void)
{
	struct pmhash *pmhash;
	size_t len = 128;
	pmhash = malloc(sizeof(*pmhash) + len * sizeof(struct item));
	if (!pmhash)
		return NULL;
	pmhash->len = len;
	memset(pmhash->items, 0, len * sizeof(struct item));
	return pmhash;
}

int pmhash_add(struct pmhash **pmhash, char *key, void *val)
{
	unsigned int i;
	struct pmhash *hash = *pmhash;
	i = 0;
repeat:
	for (; i < hash->len; i++) {
		if (hash->items[i].key == NULL) {
			hash->items[i].key = key;
			hash->items[i].val = val;
			break;
		}
	}
	if (i == hash->len) {
		struct pmhash *nhash;
		size_t len = hash->len * sizeof(struct item);
		size_t nlen = len * 2;
		nhash = realloc(hash, sizeof(*nhash) + nlen);
		if (!nhash)
			goto out;
		*pmhash = hash = nhash;
		memset(&hash->items[hash->len], 0, len);
		hash->len = hash->len * 2;
		goto repeat;
	}
	return 0;
out:
	return -1;
}

void * pmhash_get(struct pmhash *pmhash, char *key)
{
	unsigned int i;
	for (i = 0; i < pmhash->len; i++) {
		if (pmhash->items[i].key == NULL)
			return NULL;
		if (!strcmp(pmhash->items[i].key, key))
			return pmhash->items[i].val;
	}
	return NULL;
}

void pmhash_del(struct pmhash *pmhash)
{
	unsigned int i;
	for (i = 0; i < pmhash->len; i++) {
		if (pmhash->items[i].key == NULL)
			break;
		free(pmhash->items[i].key);
		free(pmhash->items[i].val);
	}
	free(pmhash);
}
