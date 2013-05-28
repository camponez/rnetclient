/*
 *  Copyright (C) 2012  Thadeu Lima de Souza Cascardo <cascardo@minaslivre.org>
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
#include <gnutls/gnutls.h>
#include <zlib.h>

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
	*olen = (buffer[3] << 8 & buffer[4]);
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

int main(int argc, char **argv)
{
	struct sockaddr_in saddr;
	int c;
	int r;
	char buffer[2048];
	char *out;
	size_t olen;
	gnutls_session_t session;
	gnutls_global_init();
	session_new(&session);
	c = socket(PF_INET, SOCK_STREAM, 0);
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(3456);
	saddr.sin_addr.s_addr = inet_addr("161.148.185.11");
	r = connect(c, (struct sockaddr *) &saddr, sizeof(saddr));
	if (r < 0) {
		fprintf(stderr, "error connecting to server: %s\n",
			strerror(errno));
		exit(1);
	}
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) c);
	buffer[0] = 1;
	write(c, buffer, 1);
	write(c, "00000000000000", 14);
	r = read(c, buffer, 1);
	if (r != 1 && buffer[0] != 'E')
		exit(1);
	r = read(c, buffer, 14);
	if (r != 14)
		exit(1);
	if ((r = gnutls_handshake(session)) < 0)
		fprintf(stderr, "error in handshake: %s\n",
				gnutls_strerror(r));
	else
		fprintf(stderr, "handshake ok\n");
	r = read(0, buffer, sizeof(buffer));
	deflateRecord(buffer, r, &out, &olen);
	gnutls_record_send(session, out, olen);
	free(out);
	while ((r = gnutls_record_recv(session, buffer, sizeof(buffer))) > 0)
		write(1, buffer, r);
	close(c);
	gnutls_global_deinit();
	return 0;
}
