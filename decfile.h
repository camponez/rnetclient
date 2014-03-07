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

#ifndef _RNET_DECFILE_H
#define _RNET_DECFILE_H

#include "rnet_message.h"

#define RNET_HEADER_SIZE_2013 765
#define RNET_HEADER_SIZE_2014 793

struct rnet_decfile;
struct rnet_decfile * rnet_decfile_open(char *filename);
void rnet_decfile_close(struct rnet_decfile *decfile);
char *rnet_decfile_get_header_field(struct rnet_decfile *decfile, char *field);

char * rnet_decfile_get_header(struct rnet_decfile *decfile);
struct rnet_message * rnet_decfile_get_file(struct rnet_decfile *decfile);
char * rnet_decfile_get_file_hash(struct rnet_decfile *decfile);

#endif
