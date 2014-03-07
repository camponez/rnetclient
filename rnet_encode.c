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

#define RNET_HEADER_START_2013 111
#define RNET_HEADER_END_2013 (RNET_HEADER_SIZE_2013 - 15)
#define RNET_HEADER_START_2014 111
#define RNET_HEADER_END_2014 (RNET_HEADER_SIZE_2014 - 15)

int rnet_encode(struct rnet_decfile *decfile, struct rnet_message **msg)
{
	int r;

	uint32_t tp_arq;
	uint32_t id_dec;
	char *cpf;
	char *codigo_recnet;
	char *ano;
	char *exerc;
	char *uf;
	uint16_t versao_pgd;
	uint64_t file_len;
	char *hash;
	char *header;
	uint8_t ret;

	size_t header_start, header_end;

	*msg = rnet_message_new();
	if (*msg == NULL) {
		return -ENOMEM;
	}

	file_len = rnet_decfile_get_file(decfile)->len;
	hash = rnet_decfile_get_file_hash(decfile);
	if (!hash)
		return -1;
	header = rnet_decfile_get_header(decfile);

	codigo_recnet = rnet_decfile_get_header_field(decfile, "codigo_recnet");
	tp_arq = strtoul(codigo_recnet, NULL, 10);
	id_dec = strtoul(rnet_decfile_get_header_field(decfile, "hash"), NULL, 10);
	cpf = rnet_decfile_get_header_field(decfile, "cpf");
	ano = rnet_decfile_get_header_field(decfile, "ano");
	exerc = rnet_decfile_get_header_field(decfile, "exerc");
	uf = rnet_decfile_get_header_field(decfile, "uf");
	versao_pgd = strtoul(rnet_decfile_get_header_field(decfile, "nr_versao"), NULL, 10);
	ret = strtoul(rnet_decfile_get_header_field(decfile, "in_ret"), NULL, 10);

	if (!strcmp(ano, "2013")) {
		header_start = RNET_HEADER_START_2013;
		header_end = RNET_HEADER_END_2013;
	} else if (!strcmp(ano, "2014")) {
		header_start = RNET_HEADER_START_2014;
		header_end = RNET_HEADER_END_2014;
	} else {
		return -EINVAL;
	}

	(*msg)->buffer[0] = 0x40;
	(*msg)->len = 1;
	r = rnet_message_add_u32(msg, "a_comp", 0);
	r = rnet_message_add_u32(msg, "tp_arq", tp_arq);
	r = rnet_message_add_u32(msg, "id_dec", id_dec);
	r = rnet_message_add_ascii(msg, "exercicio", ano);
	r = rnet_message_add_ascii(msg, "exercicio_pgd", exerc);
	r = rnet_message_add_buffer(msg, "hash_arq", hash, 16);
	r = rnet_message_add_buffer(msg, "hash_trans", hash, 16);
	r = rnet_message_add_ascii(msg, "ni", cpf);
	r = rnet_message_add_ascii(msg, "tp_ni", "CPF");
	r = rnet_message_add_u8(msg, "num_ass", 0);
	r = rnet_message_add_u32(msg, "p_comp", 0);
	r = rnet_message_add_u8(msg, "ret", ret);
	r = rnet_message_add_u64(msg, "tam_arq", file_len);
	r = rnet_message_add_u64(msg, "tam_assinado", file_len);
	r = rnet_message_add_u64(msg, "tam_trans", file_len);
	r = rnet_message_add_ascii(msg, "uf", uf);
	r = rnet_message_add_u8(msg, "vrs_des_pa", 0);
	r = rnet_message_add_u16(msg, "versao_pgd", versao_pgd);
	r = rnet_message_add_u8(msg, "critica_validador", 0x06);
	r = rnet_message_add_ascii(msg, "ip_loc", "127.0.0.1");
	r = rnet_message_add_ascii(msg, "versao_java", "1.7.0_03-icedtea;OpenJDK Runtime Environment");
	r = rnet_message_add_ascii(msg, "origem", "JA2R");
	r = rnet_message_add_ascii(msg, "so", "GNU");
	r = rnet_message_add_ascii(msg, "cliente", "201104");
	r = rnet_message_add_buffer(msg, "dados_val", header + header_start, header_end - header_start);
	r = rnet_message_add_u32(msg, "tam_dados_val", 0);
	r = rnet_message_add_u32(msg, "tam_dados_val_chave", 0);
	r = rnet_message_add_u32(msg, "arquivos_restantes", 0);

	free(hash);

	if (r < 0)
		return r;
	return 0;
}
