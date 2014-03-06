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

#define _GNU_SOURCE
#include "decfile.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <gcrypt.h>
#include "pmhash.h"
#include "rnet_message.h"

#ifndef MAX
#define MAX(a,b) (a >= b) ? a : b
#endif

struct rnet_decfile {
	char *filename;
	FILE *file;
	char **lines;
	int lines_len;
	struct pmhash *header;
	struct rnet_message *message;
};

/*
 * line should be an allocated buffer given to append_line
 * this means, free(line) will be called when decfile is released
 */
static int append_line(struct rnet_decfile *decfile, char *line)
{
	size_t len;
	char **old_lines;
	decfile->lines_len += 1;
	len = sizeof(*decfile->lines) * decfile->lines_len;
	old_lines = decfile->lines;
	decfile->lines = realloc(decfile->lines, len);
	if (!decfile->lines) {
		decfile->lines = old_lines;
		goto out;
	}
	decfile->lines[decfile->lines_len - 1] = line;
	return 0;
out:
	decfile->lines_len -= 1;
	return -ENOMEM;
}

static void decfile_release_lines(struct rnet_decfile *decfile)
{
	int i;
	for (i = 0; i < decfile->lines_len; i++)
		free(decfile->lines[i]);
	free(decfile->lines);
	decfile->lines = NULL;
}

static char * get_header(struct rnet_decfile *decfile);
static int parse_header_2013(struct pmhash *hash, char *buffer);
static int parse_header_2014(struct pmhash *hash, char *buffer);
static int decfile_parse_file(struct rnet_decfile *decfile);

static int decfile_parse_header(struct rnet_decfile *decfile)
{
	char *buffer = get_header(decfile);
	if (!buffer)
		return -EINVAL;
	switch (strlen(buffer)) {
	case 765:
		return parse_header_2013(decfile->header, buffer);
	case 793:
		return parse_header_2014(decfile->header, buffer);
	default:
		return -EINVAL;
	}
}

static int decfile_parse(struct rnet_decfile *decfile)
{
	char *buffer = NULL;
	size_t len = 0;
	int r;
	while ((r = getline(&buffer, &len, decfile->file)) > 0) {
		r = append_line(decfile, buffer);
		if (r) {
			free(buffer);
			goto out;
		}
		buffer = NULL;
		len = 0;
	}
	if (!(r = decfile_parse_header(decfile)) && !(r = decfile_parse_file(decfile)))
		return 0;
out:
	decfile_release_lines(decfile);
	return r;
}

struct rnet_decfile * rnet_decfile_open(char *filename)
{
	struct rnet_decfile *decfile;
	int r = -ENOMEM;
	decfile = malloc(sizeof(*decfile));
	if (!decfile)
		return NULL;
	decfile->header = pmhash_new();
	if (!decfile->header)
		goto out_header;
	decfile->message = rnet_message_new();
	if (!decfile->message)
		goto out_message;
	decfile->filename = strdup(filename);
	if (!decfile->filename)
		goto out_filename;
	decfile->file = fopen(filename, "r");
	if (!decfile->file)
		goto out_file;
	decfile->lines_len = 0;
	decfile->lines = NULL;
	if ((r = decfile_parse(decfile)))
		goto out_parse;
	return decfile;
out_parse:
	fclose(decfile->file);
out_file:
	free(decfile->filename);
out_filename:
	rnet_message_del(decfile->message);
out_message:
	pmhash_del(decfile->header);
out_header:
	free(decfile);
	errno = -r;
	return NULL;
}

void rnet_decfile_close(struct rnet_decfile *decfile)
{
	decfile_release_lines(decfile);
	fclose(decfile->file);
	free(decfile->filename);
	free(decfile);
}

static char * get_header(struct rnet_decfile *decfile)
{
	int i;
	for (i = 0; i < decfile->lines_len; i++) {
		if (!strncmp(decfile->lines[i], "IRPF", 4)) {
			return decfile->lines[i];
		}
	}
	return NULL;
}

static int parse_header_2014(struct pmhash *hash, char *buffer)
{
	int r;
	char *p = buffer;
	char *key;
	char *val;

#define parse(field, sz) \
	r = -ENOMEM; \
	val = malloc(sz + 1); \
	if (!val) \
		goto out_val; \
	val[sz] = 0; \
	memcpy(val, p, sz); \
	p += sz; \
	key = strdup(field); \
	if (!key) \
		goto out_key; \
	if (pmhash_add(&hash, key, val)) \
		goto out_add;

	parse("sistema", 8);
	parse("exerc", 4);
	if (strcmp(val, "2014")) {
		r = -EINVAL;
		goto out_val;
	}
	parse("ano", 4);
	parse("codigo_recnet", 4);
	parse("in_ret", 1);
	parse("cpf", 11);
	parse("filler", 3);
	parse("tipo_ni", 1);
	parse("nr_versao", 3);
	parse("nome", 60);
	parse("uf", 2);
	parse("hash", 10);
	parse("in_cert", 1);
	parse("dt_nasc", 8);
	parse("in_comp", 1);
	parse("in_res", 1);
	parse("in_gerada", 1);
	parse("nr_recibo_anterior", 10);
	parse("in_pgd", 1);
	parse("so", 14);
	parse("versao_so", 7);
	parse("jvm", 9);
	parse("nr_recibo", 10);
	parse("municipio", 4);
	parse("conjuge", 11);
	parse("obrig", 1);
	parse("impdevido", 13);
	parse("nr_recibo", 10);
	parse("in_seg", 1);
	parse("imppago", 2);
	parse("impant", 1);
	parse("mudend", 1);
	parse("cep", 8);
	parse("debito", 1);
	parse("banco", 3);
	parse("agencia", 4);
	parse("filler", 1);
	parse("data_julgado", 8);
	parse("imppagar", 13);
	parse("tribfonte", 1);
	parse("cpfrra", 11);
	parse("trib_rra", 1);
	parse("cpf_rra2", 11);
	parse("trib_3rra", 1);
	parse("cpf_rra3", 11);
	parse("trib_4rra", 1);
	parse("cpf_rra4", 11);
	parse("vr_doacao", 13);
	parse("cnpj1", 14);
	parse("cnpj2", 14);
	parse("cnpj3", 14);
	parse("cnpj4", 14);
	parse("cpf_dep1", 11);
	parse("dnas_dep1", 8);
	parse("cpf_dep2", 11);
	parse("dnas_dep2", 8);
	parse("cpf_dep3", 11);
	parse("dnas_dep3", 8);
	parse("cpf_dep4", 11);
	parse("dnas_dep4", 8);
	parse("cpf_dep5", 11);
	parse("dnas_dep5", 8);
	parse("cpf_dep6", 11);
	parse("dnas_dep6", 8);
	parse("cnpj_med1", 14);
	parse("cnpj_med2", 14);
	parse("cpf_alim", 11);
	parse("cpf_invent", 11);
	parse("municipio", 40);
	parse("contribuinte", 60);
	parse("cpf_empregada", 11);
	parse("hashcode", 12);
	parse("data_nao_residente", 8);
	parse("cpf_procurador", 11);
	parse("obrigatoriedade", 3);
	parse("rendtrib", 13);
	parse("cnpj_prev", 14);
	parse("cnpj_prev2", 14);
	parse("vr_totisentos", 13);
	parse("vr_totexclusivo", 13);
	parse("vr_totpagamentos", 13);
	parse("nr_conta", 13);
	parse("nr_dv_conta", 2);
	parse("in_dv_conta", 1);
	parse("versaotestpgd", 3);
	parse("controle", 10);

	return 0;
out_add:
	free(key);
out_key:
	free(val);
out_val:
	return r;
}

static int parse_header_2013(struct pmhash *hash, char *buffer)
{
	int r;
	char *p = buffer;
	char *key;
	char *val;

#define parse(field, sz) \
	r = -ENOMEM; \
	val = malloc(sz + 1); \
	if (!val) \
		goto out_val; \
	val[sz] = 0; \
	memcpy(val, p, sz); \
	p += sz; \
	key = strdup(field); \
	if (!key) \
		goto out_key; \
	if (pmhash_add(&hash, key, val)) \
		goto out_add;

	parse("sistema", 8);
	parse("exerc", 4);
	if (strcmp(val, "2013")) {
		r = -EINVAL;
		goto out_val;
	}
	parse("ano", 4);
	parse("codigo_recnet", 4);
	parse("in_ret", 1);
	parse("cpf", 11);
	parse("filler", 3);
	parse("tipo_ni", 1);
	parse("nr_versao", 3);
	parse("nome", 60);
	parse("uf", 2);
	parse("hash", 10);
	parse("in_cert", 1);
	parse("dt_nasc", 8);
	parse("in_comp", 1);
	parse("in_res", 1);
	parse("in_gerada", 1);
	parse("nr_recibo_anterior", 10);
	parse("in_pgd", 1);
	parse("so", 14);
	parse("versao_so", 7);
	parse("jvm", 9);
	parse("nr_recibo", 10);
	parse("municipio", 4);
	parse("conjuge", 11);
	parse("obrig", 1);
	parse("impdevido", 13);
	parse("nr_recibo", 10);
	parse("in_seg", 1);
	parse("imppago", 2);
	parse("impant", 1);
	parse("mudend", 1);
	parse("cep", 8);
	parse("debito", 1);
	parse("banco", 3);
	parse("agencia", 4);
	parse("filler", 1);
	parse("data_julgado", 8);
	parse("imppagar", 13);
	parse("tribfonte", 1);
	parse("cpfrra", 11);
	parse("trib_rra", 1);
	parse("cpf_rra2", 11);
	parse("trib_3rra", 1);
	parse("cpf_rra3", 11);
	parse("vr_doacao", 13);
	parse("cnpj1", 14);
	parse("cnpj2", 14);
	parse("cnpj3", 14);
	parse("cnpj4", 14);
	parse("cpf_dep1", 11);
	parse("dnas_dep1", 8);
	parse("cpf_dep2", 11);
	parse("dnas_dep2", 8);
	parse("cpf_dep3", 11);
	parse("dnas_dep3", 8);
	parse("cpf_dep4", 11);
	parse("dnas_dep4", 8);
	parse("cpf_dep5", 11);
	parse("dnas_dep5", 8);
	parse("cpf_dep6", 11);
	parse("dnas_dep6", 8);
	parse("cnpj_med1", 14);
	parse("cnpj_med2", 14);
	parse("cpf_alim", 11);
	parse("cpf_invent", 11);
	parse("municipio", 40);
	parse("contribuinte", 60);
	parse("cpf_empregada", 11);
	parse("hashcode", 12);
	parse("data_nao_residente", 8);
	parse("cpf_procurador", 11);
	parse("obrigatoriedade", 3);
	parse("rendtrib", 13);
	parse("cnpj_prev", 14);
	parse("cnpj_prev2", 14);
	parse("vr_totisentos", 13);
	parse("vr_totexclusivo", 13);
	parse("vr_totpagamentos", 13);
	parse("versaotestpgd", 3);
	parse("controle", 10);

	return 0;
out_add:
	free(key);
out_key:
	free(val);
out_val:
	return r;
}

char *rnet_decfile_get_header_field(struct rnet_decfile *decfile, char *field)
{
	return pmhash_get(decfile->header, field);
}

/* returns true if register is declaration and not a receipt */
static int decfile_reg_is_dec(char *line)
{
	if (line[0] >= '0' && line[0] <= '9' &&
	    line[1] >= '0' && line[1] <= '9')
		return 1;
	if (!strncmp(line, "IRPF    ", 8))
		return 1;
	if (!strncmp(line, "T9", 2))
		return 1;
	return 0;
}

/* strip a register from its control number and append it to message */
static int append_stripped_reg_ctrl(struct rnet_message **message, char *line)
{
	size_t len;
	struct rnet_message *msg = *message;
	int growth;
	if (!decfile_reg_is_dec(line))
		return 0;
	len = strlen(line);
	if (len < 12)
		return -EINVAL;
	growth = msg->len + len - 10 - msg->alen;
	if (growth > 0) {
		if (rnet_message_expand(message, growth))
			return -ENOMEM;
		msg = *message;
	}
	memcpy(&msg->buffer[msg->len], line, len - 12);
	msg->buffer[msg->len + len - 12] = '\r';
	msg->buffer[msg->len + len - 11] = '\n';
	msg->len += len - 10;
	return 0;
}

static int decfile_parse_file(struct rnet_decfile *decfile)
{
	int i;
	int r;
	for (i = 0; i < decfile->lines_len; i++) {
		r = append_stripped_reg_ctrl(&decfile->message,
						decfile->lines[i]);
		if (r)
			return r;
	}
	return 0;
}

struct rnet_message * rnet_decfile_get_file(struct rnet_decfile *decfile)
{
	return decfile->message;
}

char * rnet_decfile_get_file_hash(struct rnet_decfile *decfile)
{
	char *hash;
	size_t len;
	if (gcry_md_test_algo(GCRY_MD_MD5))
		return NULL;
	len = gcry_md_get_algo_dlen(GCRY_MD_MD5);
	hash = malloc(len);
	if (!hash)
		return NULL;
	gcry_md_hash_buffer(GCRY_MD_MD5, hash, decfile->message->buffer,
					decfile->message->len);
	return hash;
}

char * rnet_decfile_get_header(struct rnet_decfile *decfile)
{
	return get_header(decfile);
}
