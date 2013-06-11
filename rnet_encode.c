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

#include "rnet_encode.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "rnet_message.h"
#include "decfile.h"

int rnet_encode(struct rnet_decfile *decfile, struct rnet_message **msg)
{
	int r;
	uint32_t tp_arq;
	uint32_t id_dec;
	char *cpf;
	char *codigo_recnet;
	char *ano;
	char *exerc;
	*msg = rnet_message_new();
	if (*msg == NULL) {
		return -ENOMEM;
	}

	codigo_recnet = rnet_decfile_get_header_field(decfile, "codigo_recnet");
	tp_arq = strtoul(codigo_recnet, NULL, 10);
	id_dec = strtoul(rnet_decfile_get_header_field(decfile, "hash"), NULL, 10);
	cpf = rnet_decfile_get_header_field(decfile, "cpf");
	ano = rnet_decfile_get_header_field(decfile, "ano");
	exerc = rnet_decfile_get_header_field(decfile, "exerc");

	(*msg)->buffer[0] = 0x40;
	(*msg)->len = 1;
	r = rnet_message_add_u32(*msg, "a_comp", 0);
	r = rnet_message_add_u32(*msg, "tp_arq", tp_arq);
	r = rnet_message_add_u32(*msg, "id_dec", id_dec);
	r = rnet_message_add_ascii(*msg, "exercicio", ano);
	r = rnet_message_add_ascii(*msg, "exercicio_pgd", exerc);
	r = rnet_message_add_ascii(*msg, "ni", cpf);
	r = rnet_message_add_ascii(*msg, "tipo_ni", "CPF");
	if (r < 0)
		return r;
	return 0;
}
