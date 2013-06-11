/*
 *  Copyright (C) 2013  Thadeu Lima de Souza Cascardo <cascardo@minaslivre.org>
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

#include "rnet_message.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

#ifndef MAX
#define MAX(a,b) (a >= b) ? a : b
#endif

static int rnet_message_expand(struct rnet_message **message, size_t len)
{
	struct rnet_message *msg = *message;
	struct rnet_message *nmsg;
	if (msg)
		len += msg->alen;
	nmsg = realloc(msg, sizeof(*msg) + len);
	if (!nmsg)
		return -1;
	nmsg->alen = len;
	if (!msg)
		nmsg->len = 0;
	*message = nmsg;
	return 0;
}

struct rnet_message * rnet_message_new(void)
{
	struct rnet_message *msg = NULL;
	int r;
	r = rnet_message_expand(&msg, 1118);
	if (r)
		return NULL;
	return msg;
}

void rnet_message_del(struct rnet_message *message)
{
	free(message);
}

static int add_field(struct rnet_message *msg, char *key, int klen, char *val, int vlen)
{
	int n = 0;
	char *buffer;
	if ((msg->alen - msg->len) < (klen + vlen + 3)) {
		if (rnet_message_expand(&msg, MAX(msg->len, klen + vlen + 3)))
			return -ENOMEM;
	}
	buffer = msg->buffer + msg->len;
	if (klen > 0x7f || klen < 0)
		return -EINVAL;
	if (vlen > 0x7fff || vlen < 0)
		return -EINVAL;
	buffer[0] = klen & 0x7f;
	if (vlen > 0x7f)
		buffer[0] |= 0x80;
	buffer++;
	n++;
	memcpy(buffer, key, klen);
	buffer += klen;
	n += klen;
	if (vlen > 0x7f) {
		buffer[0] = (vlen >> 8) & 0x7f;
		buffer[1] = vlen & 0xff;
		buffer += 2;
		n += 2;
	} else {
		buffer[0] = vlen & 0x7f;
		buffer++;
		n++;
	}
	memcpy(buffer, val, vlen);
	n += vlen;
	msg->len += n;
	return n;
}

int rnet_message_add_u32(struct rnet_message *msg, char *key, uint32_t val)
{
	uint32_t nval = htonl(val);
	return add_field(msg, key, strlen(key), (char *) &nval, sizeof(val));
}

int rnet_message_add_ascii(struct rnet_message *msg, char *key, char *val)
{
	return add_field(msg, key, strlen(key), val, strlen(val));
}
