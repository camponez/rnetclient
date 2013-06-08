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

struct rnet_decfile {
	char *filename;
	FILE *file;
	char **lines;
	int lines_len;
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
	return -1;
}

static void decfile_release_lines(struct rnet_decfile *decfile)
{
	int i;
	for (i = 0; i < decfile->lines_len; i++)
		free(decfile->lines[i]);
	free(decfile->lines);
	decfile->lines = NULL;
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
	return 0;
out:
	decfile_release_lines(decfile);
	return -1;
}

struct rnet_decfile * rnet_decfile_open(char *filename)
{
	struct rnet_decfile *decfile;
	decfile = malloc(sizeof(*decfile));
	if (!decfile)
		return NULL;
	decfile->filename = strdup(filename);
	if (!decfile->filename)
		goto out_filename;
	decfile->file = fopen(filename, "r");
	if (!decfile->file)
		goto out_file;
	decfile->lines_len = 0;
	decfile->lines = NULL;
	if (decfile_parse(decfile))
		goto out_parse;
	return decfile;
out_parse:
	fclose(decfile->file);
out_file:
	free(decfile->filename);
out_filename:
	free(decfile);
	return NULL;
}

void rnet_decfile_close(struct rnet_decfile *decfile)
{
	decfile_release_lines(decfile);
	fclose(decfile->file);
	free(decfile->filename);
	free(decfile);
}
