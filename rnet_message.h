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

#ifndef _RNET_MESSAGE_H
#define _RNET_MESSAGE_H

#include <stdint.h>

struct rnet_message {
	int len;
	int alen;
	char buffer[];
};

struct rnet_message * rnet_message_new(void);
void rnet_message_del(struct rnet_message *message);

int rnet_message_add_u32(struct rnet_message *msg, char *key, uint32_t val);
int rnet_message_add_ascii(struct rnet_message *msg, char *key, char *val);
int rnet_message_add_u8(struct rnet_message *msg, char *key, uint8_t val);
int rnet_message_add_u16(struct rnet_message *msg, char *key, uint16_t val);

#endif
