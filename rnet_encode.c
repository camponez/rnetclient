/*
 *  Copyright (C) 2013-2014  Thadeu Lima de Souza Cascardo <cascardo@minaslivre.org>
 *  Copyright (C) 2014  Alexandre Oliva <lxoliva@fsfla.org>
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
	int r = -EIO;

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

	size_t header_size, header_head, header_tail;

	*msg = rnet_message_new();
	if (*msg == NULL) {
		return -ENOMEM;
	}

	file_len = rnet_decfile_get_file(decfile)->len;
	hash = rnet_decfile_get_file_hash(decfile);
	if (!hash)
		goto out;
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

	if (!strcmp(exerc, "2015")) {
		header_size = RNET_HEADER_SIZE_2015;
		header_head = RNET_HEADER_HEAD_2015;
		header_tail = RNET_HEADER_TAIL_2015;
	} else if (!strcmp(exerc, "2014")) {
		header_size = RNET_HEADER_SIZE_2014;
		header_head = RNET_HEADER_HEAD_2014;
		header_tail = RNET_HEADER_TAIL_2014;
	} else if (!strcmp(exerc, "2013")) {
		header_size = RNET_HEADER_SIZE_2013;
		header_head = RNET_HEADER_HEAD_2013;
		header_tail = RNET_HEADER_TAIL_2013;
	} else {
		r = -EINVAL;
		goto out2;
	}

	/* This was already checked at parse time.  */
	if (strlen (header) != header_size)
		abort ();

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
	r = rnet_message_add_ascii(msg, "versao_java", "1.5.0-gij;Free Software rnetclient pretending to be GNU Interpreter for Java");
	r = rnet_message_add_ascii(msg, "origem", "JA2R");
	r = rnet_message_add_ascii(msg, "so", "GNU");
	r = rnet_message_add_ascii(msg, "cliente", "201105");
	r = rnet_message_add_buffer(msg, "dados_val",
				    header + header_head,
				    header_size - header_tail - header_head);
	r = rnet_message_add_u32(msg, "tam_dados_val", 0);
	r = rnet_message_add_u32(msg, "tam_dados_val_chave", 0);
	r = rnet_message_add_u32(msg, "arquivos_restantes", 0);

	free(hash);

	if (r < 0)
		goto out;
	return 0;

out2:
	free(hash);
out:
	rnet_message_del(*msg);
	return r;
}
