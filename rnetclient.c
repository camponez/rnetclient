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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <gnutls/gnutls.h>
#include <zlib.h>
#include "decfile.h"
#include "rnet_message.h"
#include "rnet_encode.h"

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

static int deflateRecord(char *buffer, size_t len, char **out, size_t *olen)
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
	zstrm.next_in = buffer;
	zstrm.avail_in = len;
	zstrm.next_out = *out + 6;
	zstrm.avail_out = len * 2 + 30;
	while ((r = deflate(&zstrm, Z_FINISH)) != Z_STREAM_END &&
		zstrm.avail_out > 0);
	if ((r = deflate(&zstrm, Z_FINISH)) != Z_STREAM_END) {
		deflateEnd(&zstrm);
		free(*out);
		return -1;
	}
	*olen = zstrm.avail_out + 6;
	(*out)[0] = 0x1;
	(*out)[1] = (zstrm.avail_out >> 8);
	(*out)[2] = (zstrm.avail_out & 0xff);
	(*out)[3] = (len >> 8);
	(*out)[4] = (len & 0xff);
	(*out)[5] = 0x1;
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
	*olen = (buffer[3] << 8 | buffer[4]);
	*out = malloc(*olen);
	if (!out) {
		inflateEnd(&zstrm);
		return -1;
	}
	zstrm.next_in = buffer + 6;
	zstrm.avail_in = len - 6;
	zstrm.next_out = *out;
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
	struct sockaddr_in saddr;
	int r;
	int fd = *c = -1;
	int i;
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
	write(c, buffer, 1);
	write(c, "00000000000000", 14);
	r = read(c, buffer, 1);
	if (r != 1 && buffer[0] != 'E')
		return -1;
	r = read(c, buffer, 14);
	if (r != 14)
		return -1;
	return 0;
}

static void usage(void)
{
	fprintf(stderr, "rnetclient [filename]\n");
	exit(1);
}

static int rnet_send(gnutls_session_t session, char *buffer, size_t len)
{
	char *out;
	size_t olen;
	deflateRecord(buffer, len, &out, &olen);
	gnutls_record_send(session, out, olen);
	free(out);
	return 0;
}

static int rnet_recv(gnutls_session_t session, struct rnet_message **message)
{
	char *out;
	size_t olen;
	int r;
	char *buffer;
	size_t len;
	rnet_message_expand(message, 6);
	buffer = (*message)->buffer;
	r = gnutls_record_recv(session, buffer, 6);
	len = (buffer[1] << 8 | buffer[2]);
	rnet_message_expand(message, len);
	buffer = (*message)->buffer + 6;
	r = gnutls_record_recv(session, buffer, len);
	inflateRecord(buffer - 6, len + 6, &out, &olen);
	rnet_message_del(*message);
	*message = NULL;
	rnet_message_expand(message, olen);
	memcpy((*message)->buffer, out, olen);
	(*message)->len = olen;
	free(out);
	return 0;
}

static void save_rec_file(char *cpf, char *buffer, int len)
{
	int fd;
	char *filename;
	char *home, *tmpdir;
	mode_t mask;
	size_t fnlen;
	int r;
	home = getenv("HOME");
	if (!home) {
		tmpdir = getenv("TMPDIR");
		if (!tmpdir)
			tmpdir = "/tmp";
		home = tmpdir;
	}
	fnlen = strlen(home) + strlen(cpf) + 13;
	filename = malloc(fnlen);
	snprintf(filename, fnlen, "%s/%s.REC.XXXXXX", home, cpf);
	mask = umask(0177);
	fd = mkstemp(filename);
	if (fd < 0) {
		fprintf(stderr, "Could not create receipt file: %s\n",
						strerror(errno));
		goto out;
	}
	r = write(fd, buffer, len);
	if (r != len) {
		fprintf(stderr, "Could not write to receipt file%s%s\n",
			r < 0 ? ": " : ".",
			r < 0 ? strerror(errno) : "");
		goto out;
	}
	fprintf(stderr, "Wrote the receipt to %s.\n", filename);
out:
	close(fd);
	free(filename);
	umask(mask);
}

static void handle_response_already_found(char *cpf, struct rnet_message *message)
{
	char *value;
	int vlen;
	if (!rnet_message_parse(message, "texto", &value, &vlen))
		fprintf(stderr, "%.*s\n", vlen, value);
	if (!rnet_message_parse(message, "arquivo", &value, &vlen))
		save_rec_file(cpf, value, vlen);
}

int main(int argc, char **argv)
{
	int c;
	int r;
	struct rnet_decfile *decfile;
	struct rnet_message *message = NULL;
	gnutls_session_t session;
	int finish = 0;
	char *cpf;
	
	if (argc < 2) {
		usage();
	}

	decfile = rnet_decfile_open(argv[1]);
	if (!decfile) {
		fprintf(stderr, "could not parse %s: %s\n", argv[1], strerror(errno));
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
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) c);
	r = handshake(c);
	if (r < 0) {
		exit(1);
	}
	if ((r = gnutls_handshake(session)) < 0)
		fprintf(stderr, "error in handshake: %s\n",
				gnutls_strerror(r));

	rnet_encode(decfile, &message);
	rnet_send(session, message->buffer, message->len);
	rnet_message_del(message);

	message = NULL;
	r = rnet_recv(session, &message);
	if (r || !message || message->len == 0) {
		fprintf(stderr, "error when receiving response\n");
		goto out;
	}
	switch (message->buffer[0]) {
	case 1: /* go ahead */
		break;
	case 3: /* error */
		finish = 1;
		break;
	case 4:
		handle_response_already_found(cpf, message);
		finish = 1;
		break;
	case 2:
	case 5:
		finish = 1;
		break;
	}
	rnet_message_del(message);

	if (finish)
		goto out;

	message = rnet_decfile_get_file(decfile);
	rnet_send(session, message->buffer, message->len);

	message = NULL;
	r = rnet_recv(session, &message);
	if (r || !message || message->len == 0) {
		fprintf(stderr, "error when receiving response\n");
		goto out;
	}
	switch (message->buffer[0]) {
	case 3: /* error */
		finish = 1;
		break;
	case 2:
	case 4:
	case 5:
	case 1:
		finish = 1;
		break;
	}
	
out:
	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	close(c);
	rnet_decfile_close(decfile);
	gnutls_global_deinit();

	return 0;
}
