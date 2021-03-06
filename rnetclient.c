/*
 *  Copyright (C) 2012-2014  Thadeu Lima de Souza Cascardo <cascardo@minaslivre.org>
 *  Copyright (C) 2014  Alexandre Oliva <lxoliva@fsfla.org>
 *  Copyright (C) 2014  Sergio Durigan Junior <sergiodj@sergiodj.net>
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <gnutls/gnutls.h>
#include <zlib.h>
#include <argp.h>
#include "config.h"
#include "decfile.h"
#include "rnet_message.h"
#include "rnet_encode.h"

/* Program version and bug report address.  */

const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

/* Documentation strings.  */

static const char rnetclient_doc[] =
	"Send the Brazilian Income Tax Report to the Brazilian "
	"Tax Authority";
static const char rnetclient_args_doc[] =
	"[-d|--declaration] FILE [-o|--output-dir DIRECTORY]";

/* Description and definition of each option accepted by the program.  */

static const struct argp_option rnetclient_options_desc[] = {
	{ "declaration", 'd', "FILE", 0,
	  "The Income Tax Report file that will be sent.",
	  0 },

	{ "output-dir", 'o', "DIRECTORY", 0,
	  "The directory where you wish to save the receipt.",
	  0 },

	{ NULL },
};

struct rnetclient_args {
	/* File representing the declaration.  */
	char *input_file;

	/* Output directory to save the receipt.  */
	char *output_dir;
};

/* Parser for command line arguments.  */

static error_t rnetclient_parse_opt(int key, char *arg, struct argp_state *state)
{
	struct rnetclient_args *a = state->input;
	switch (key) {
	case 'd':
		/* The user has explicitly provided a filename through
		   the '-d' switch.  */
		a->input_file = arg;
		break;

	case 'o':
		a->output_dir = arg;
		break;

	case ARGP_KEY_ARG:
		/* The user has possibly provided a filename without
		   using any switches (e.g., by running './rnetclient
		   file').  */
		a->input_file = arg;
		break;

	case ARGP_KEY_END:
		/* We have reached the end of the argument parsing.
		   Let's check if the user has provided a filename.  */
		if (a->input_file == NULL)
			argp_error(state,
				   "You need to provide the Income Tax Declaration "
				   "filename.");
	}

	return 0;
}

/* Control struct used by argp.  */

static struct argp rnetclient_argp = {
	rnetclient_options_desc,
	rnetclient_parse_opt,
	rnetclient_args_doc,
	rnetclient_doc,
	NULL, NULL, NULL
};

static size_t chars2len (unsigned char buf[2]) {
	return (buf[0] << 8 | buf[1]);
}

static void * get_creds(char *certfile)
{
	static gnutls_certificate_credentials_t cred;
	gnutls_certificate_allocate_credentials(&cred);
	gnutls_certificate_set_x509_trust_file(cred, certfile,
					GNUTLS_X509_FMT_PEM);
	return cred;
}

static void session_new(gnutls_session_t *session)
{
	static void *cred;
	cred = get_creds("cert.pem");
	gnutls_init(session, GNUTLS_CLIENT);
	gnutls_set_default_priority(*session);
	gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, cred);
}

static int deflateRecord(char *buffer, size_t len, char **out, size_t *olen, int header)
{
	z_stream zstrm;
	int r;
	zstrm.zalloc = Z_NULL;
	zstrm.zfree = Z_NULL;
	zstrm.opaque = Z_NULL;
	if ((r = deflateInit(&zstrm, Z_DEFAULT_COMPRESSION)) != Z_OK)
		return -1;
	*out = malloc(len * 2 + 36);
	if (!out) {
		deflateEnd(&zstrm);
		return -1;
	}
	zstrm.next_in = (z_const Bytef *) buffer;
	zstrm.avail_in = len;
	zstrm.next_out = (Bytef *) *out + 6;
	zstrm.avail_out = len * 2 + 30;
	while ((r = deflate(&zstrm, Z_FINISH)) != Z_STREAM_END &&
		zstrm.avail_out > 0);
	if ((r = deflate(&zstrm, Z_FINISH)) != Z_STREAM_END) {
		deflateEnd(&zstrm);
		free(*out);
		return -1;
	}
	*olen = zstrm.total_out + 6;
	(*out)[0] = 0x1;
	(*out)[1] = (zstrm.total_out >> 8);
	(*out)[2] = (zstrm.total_out & 0xff);
	(*out)[3] = (len >> 8);
	(*out)[4] = (len & 0xff);
	(*out)[5] = header ? 0x01 : 0x0;
	deflateEnd(&zstrm);
	return 0;
}

static int inflateRecord(char *buffer, size_t len, char **out, size_t *olen)
{
	z_stream zstrm;
	int r;
	zstrm.zalloc = Z_NULL;
	zstrm.zfree = Z_NULL;
	zstrm.opaque = Z_NULL;
	if ((r = inflateInit(&zstrm)) != Z_OK)
		return -1;
	*olen = chars2len((unsigned char *) buffer+3);
	*out = malloc(*olen);
	if (!out) {
		inflateEnd(&zstrm);
		return -1;
	}
	zstrm.next_in = (z_const Bytef *) buffer + 6;
	zstrm.avail_in = len - 6;
	zstrm.next_out = (Bytef *) *out;
	zstrm.avail_out = *olen;
	while ((r = inflate(&zstrm, Z_FINISH)) != Z_STREAM_END &&
		zstrm.avail_out > 0);
	if ((r = inflate(&zstrm, Z_FINISH)) != Z_STREAM_END) {
		inflateEnd(&zstrm);
		free(*out);
		return -1;
	}
	inflateEnd(&zstrm);
	return 0;
}

#define RNET_ADDRESS "receitanet.receita.fazenda.gov.br"

static int connect_rnet(int *c)
{
	struct addrinfo *addresses;
	struct addrinfo *addr;
	struct addrinfo hint;
	int r;
	int fd = *c = -1;
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_flags = AI_ADDRCONFIG;
	r = getaddrinfo(RNET_ADDRESS, "3456", &hint, &addresses);
	if (r) {
		return r;
	}
	for (addr = addresses; addr != NULL; addr = addr->ai_next) {
		fd = socket(addr->ai_family, addr->ai_socktype,
				addr->ai_protocol);
		if (fd >= 0)
			if (!(r = connect(fd, addr->ai_addr,
						addr->ai_addrlen)))
				break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(addresses);
	*c = fd;
	if (fd == -1)
		return EAI_SYSTEM;
	return 0;
}

static int handshake(int c)
{
	char buffer[16];
	int r;
	buffer[0] = 1;
	r = write(c, buffer, 1);
	if (r < 1)
		return -1;
	r = write(c, "00000000000000", 14);
	if (r < 14)
		return -1;
	r = read(c, buffer, 1);
	if (r != 1 && buffer[0] != 'E')
		return -1;
	r = read(c, buffer, 14);
	if (r != 14)
		return -1;
	return 0;
}

static int rnet_send(gnutls_session_t session, char *buffer, size_t len, int header)
{
	int r = 0;
	/* Large files have to be uploaded as multiple
	   separately-deflated chunks, because the compressed and
	   uncompressed lengths in each record are encoded in unsigned
	   16-bit integers each.

	   The header can't be split into multiple chunks, and it
	   should never have to, since it won't ever get even close to
	   64KiB.

	   The uploaded file may be larger: to upload such large
	   files, it suffices to send multiple records till the entire
	   file is transferred, without waiting for a response.  Since
	   we've alread informed the server of the file size in the
	   header, it knows exactly how much data to expect before
	   sending a response.  It will only send an error message
	   before that if it times us out.

	   Odds are that any reasonably large size will do, but it
	   can't be too close to 64KiB, otherwise there won't be room
	   for the compressed length should it not compress well,
	   which should never happen for capital-ASCII-only
	   declaration files, but who knows?

	   This chunk size worked at the first try, uploading a
	   ~100KiB file, so let's stick with it.  */
	const unsigned int maxc = 64472;
	if (header && len > maxc)
		return -1;

	do {
		char *out = NULL;
		size_t olen;
		size_t clen = len < maxc ? len : maxc;
		r = deflateRecord(buffer, clen, &out, &olen, header);
		if (!r) {
			size_t n = gnutls_record_send(session, out, olen);
			if (n != olen)
				r = -1;
		}
		free(out);
		buffer += clen;
		len -= clen;
	} while (len && !r);
	return r;
}

static int rnet_recv(gnutls_session_t session, struct rnet_message **message)
{
	char *out = NULL;
	size_t olen = 0;
	char *buffer;
	size_t len;
	rnet_message_expand(message, 6);
	buffer = (*message)->buffer;
	gnutls_record_recv(session, buffer, 6);
	if (buffer[0] == 0x01) {
		len = chars2len((unsigned char *) buffer+1);
		rnet_message_expand(message, len);
		buffer = (*message)->buffer + 6;
		gnutls_record_recv(session, buffer, len);
		inflateRecord(buffer - 6, len + 6, &out, &olen);
		rnet_message_del(*message);
		*message = NULL;
		rnet_message_expand(message, olen);
		memcpy((*message)->buffer, out, olen);
		(*message)->len = olen;
		free(out);
	} else {
		len = chars2len((unsigned char *) buffer+1);
		rnet_message_expand(message, len - 1);
		buffer = (*message)->buffer + 6;
		gnutls_record_recv(session, buffer, len - 1);
		(*message)->len = len + 4;
		rnet_message_strip(*message, 4);
	}
	return 0;
}

static void save_rec_file(char *cpf, char *buffer, int len, const struct rnetclient_args *args)
{
	int fd;
	char cwd[PATH_MAX];
	char *path, *fname, *tmp;
	size_t fname_len;
	ssize_t r;
	/* If the user provided the output directory where she wishes
	   to save the receipt, then we use it.  Otherwise, we save
	   the file in the current working directory (CWD).  */
	if (args->output_dir == NULL)
		path = getcwd(cwd, PATH_MAX);
	else {
		struct stat st;
		if (stat(args->output_dir, &st) < 0) {
			fprintf(stderr, "Could not stat directory \"%s\": %s\n", args->output_dir, strerror(errno));
			return;
		}
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "Error: \"%s\" is a not a directory.\n", args->output_dir);
			return;
		}
		path = args->output_dir;
	}
	/* Now it's time to decide which filename to write.  We use
	   the declaration's filename as a base layout, because the
	   proprietary version of the IRPF program only recognizes
	   receipts if they have the same name as the declaration
	   files (disconsidering the extensions).  For example, if the
	   declaration file is named "123.DEC", the receipt should be
	   named "123.REC".  Therefore, if the declaration file has
	   the ".DEC" extension, we strip it out and add the ".REC".
	   Otherwise, we use the default template, which is to save
	   the receipt with the name "$CPF.REC".  */
	tmp = strstr(args->input_file, ".DEC");
	if (tmp != NULL && tmp[sizeof(".DEC") - 1] == '\0') {
		char *p;
		/* We found the ".REC" extension.  */
		p = strdup(basename(args->input_file));
		/* Replacing the ".DEC" by ".REC".  Fortunately, we
		   just have to change one letter.  */
		tmp = strstr(p, ".DEC");
		tmp[1] = 'R';
		fname_len = strlen(p) + strlen(path) + 2;
		fname = alloca(fname_len);
		snprintf(fname, fname_len, "%s/%s", path, p);
		free(p);
	} else {
		/* The declaration filename does not follow the
		   convention, so we will not use it as a template.
		   We just generate a filename using "$CPF.REC".  */
		fname_len = strlen(cpf) + strlen(path) + sizeof(".REC") + 2;
		fname = alloca(fname_len);
		snprintf(fname, fname_len, "%s/%s.REC", path, cpf);
	}
	/* Now, open the file and write.  */
	fd = open(fname, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "Could not create receipt file \"%s\": %s\n", fname, strerror(errno));
		return;
	}
	do {
		r = write(fd, buffer, len);
	} while (r < 0 && errno == EAGAIN);
	if (r != len)
		fprintf(stderr, "Could not write to receipt file: %s", strerror(errno));
	else
		fprintf(stderr, "Wrote the receipt file to %s.\n", fname);
	close(fd);
}

static void handle_response_text_and_file(char *cpf, struct rnet_message *message, const struct rnetclient_args *args)
{
	char *value;
	int vlen;
	if (!rnet_message_parse(message, "texto", &value, &vlen))
		fprintf(stderr, "%.*s\n", vlen, value);
	if (!rnet_message_parse(message, "arquivo", &value, &vlen))
		save_rec_file(cpf, value, vlen, args);
}

static void handle_response_already_found(char *cpf, struct rnet_message *message, const struct rnetclient_args *args)
{
	handle_response_text_and_file(cpf, message, args);
}

static void handle_response_error(struct rnet_message *message)
{
	char *value;
	int vlen;
	if (!rnet_message_parse(message, "texto", &value, &vlen))
		fprintf(stderr, "%.*s\n", vlen, value);
	fprintf(stderr, "Error transmiting DEC file.\n");
}

int main(int argc, char **argv)
{
	int c;
	int r;
	struct rnet_decfile *decfile;
	struct rnet_message *message = NULL;
	struct rnetclient_args rnet_args;
	gnutls_session_t session;
	int finish = 0;
	char *cpf;
	error_t err;

	/* Parsing the command line arguments.  The argp_parse
	   function calls exit() if there is some error during the
	   parsing process (e.g., the user has provided an unknown
	   flag or the parsing function has called argp_error).
	   However, if our internal parsing function returns something
	   different than zero, then argp_parse returns this value to
	   us.  This is a bug, and should not happen in the current
	   state.  */
	memset(&rnet_args, 0, sizeof (rnet_args));
	err = argp_parse (&rnetclient_argp, argc, argv, 0, NULL, &rnet_args);
	if (err != 0)
		fprintf(stderr, "internal error while parsing command line arguments.");

	decfile = rnet_decfile_open(rnet_args.input_file);
	if (!decfile) {
		fprintf(stderr, "could not parse file \"%s\": %s\n", rnet_args.input_file, strerror(errno));
		exit(1);
	}

	cpf = rnet_decfile_get_header_field(decfile, "cpf");

	gnutls_global_init();

	session_new(&session);
	r = connect_rnet(&c);
	if (r) {
		fprintf(stderr, "error connecting to server: %s\n",
			r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		exit(1);
	}
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(intptr_t) c);
	r = handshake(c);
	if (r < 0) {
		exit(1);
	}
	if ((r = gnutls_handshake(session)) < 0)
		fprintf(stderr, "error in handshake: %s\n",
				gnutls_strerror(r));

	r = rnet_encode(decfile, &message);
	if (r < 0) {
		fprintf(stderr, "error encoding message, file not supported?\n");
		goto out;
	}

	rnet_send(session, message->buffer, message->len, 1);
	rnet_message_del(message);

	message = NULL;
	r = rnet_recv(session, &message);
	if (r || !message || message->len == 0) {
		fprintf(stderr, "error when receiving response\n");
		goto out;
	}
	switch (message->buffer[0]) {
	case 1: /* go ahead */
		handle_response_text_and_file(cpf, message, &rnet_args);
		break;
	case 3: /* error */
		handle_response_error(message);
		finish = 1;
		break;
	case 4:
		handle_response_already_found(cpf, message, &rnet_args);
		finish = 1;
		break;
	case 2:
	case 5:
		handle_response_text_and_file(cpf, message, &rnet_args);
		finish = 1;
		break;
	}
	rnet_message_del(message);

	if (finish)
		goto out;

	message = rnet_decfile_get_file(decfile);
	rnet_send(session, message->buffer, message->len, 0);

	message = NULL;
	r = rnet_recv(session, &message);
	if (r || !message || message->len == 0) {
		fprintf(stderr, "error when receiving response\n");
		goto out;
	}
	switch (message->buffer[0]) {
	case 3: /* error */
		handle_response_error(message);
		break;
	case 2:
	case 4:
	case 5:
	case 1:
		handle_response_text_and_file(cpf, message, &rnet_args);
		break;
	}
	
out:
	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	close(c);
	rnet_decfile_close(decfile);
	gnutls_global_deinit();

	return 0;
}
