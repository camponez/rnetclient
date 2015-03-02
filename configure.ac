dnl Autoconf configure script for rnetclient.
dnl Copyright (C) 2013-2014  Thadeu Lima de Souza Cascardo <cascardo@minaslivre.org>
dnl Copyright (C) 2014  Sergio Durigan Junior <sergiodj@sergiodj.net>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program.  If not, see <http://www.gnu.org/licenses/>.

dnl Run ./bootstrap.sh on the source directory in order to process this
dnl file.

dnl Initialization routines.
AC_INIT([rnetclient], [2015.0], [softwares-impostos@fsfla.org], [],
	[http://wiki.libreplanetbr.org/rnetclient])
dnl If you update this auxiliary directory, remember to also update the
dnl value of $AUX_DIR in the 'bootstrap.sh' script.
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE

dnl Do we have a usable compiler and 'install'?
AC_PROG_CC
AC_PROG_INSTALL
AC_LANG_WERROR

dnl Checking for GNUTLS.
AC_SEARCH_LIBS([gnutls_init], [gnutls],	[],
	AC_MSG_ERROR([could not find gnutls]))

dnl Checking for libgcrypt.
AC_SEARCH_LIBS([gcry_cipher_open], [gcrypt], [],
	AC_MSG_ERROR([could not find libgcrypt]))

dnl Checking for zlib.
AC_SEARCH_LIBS([zlibVersion], [z], [],
	AC_MSG_ERROR([could not find zlib]))

dnl Setting useful flags.
CFLAGS="`pkg-config --cflags gnutls 2> /dev/null` \
`pkg-config --cflags zlib 2> /dev/null` \
-Wall -Werror -Wextra -Wunused -Wunused-variable \
$CFLAGS"

dnl Outputting the necessary files for the build.
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT([Makefile]
	  [doc/Makefile]
	  [doc/man/Makefile]
	  [doc/man/pt_BR/Makefile])
