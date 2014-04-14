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
AC_INIT([rnetclient], [2014.1], [softwares-impostos@fsfla.org], [],
	[http://wiki.libreplanetbr.org/rnetclient])
dnl If you update this auxiliary directory, remember to also update the
dnl value of $AUX_DIR in the 'bootstrap.sh' script.
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE

dnl Do we have a usable compiler and 'install'?
AC_PROG_CC
AC_PROG_INSTALL

dnl Checking for GNUTLS and libgcrypt.
PKG_CHECK_MODULES(GNUTLS, gnutls >= 1.4.0, , AC_MSG_ERROR(Could not find gnutls))
AM_PATH_LIBGCRYPT(,,AC_MSG_ERROR(Could not find gcrypt))

dnl Setting useful flags.
LIBS="$LIBGCRYPT_LIBS $GNUTLS_LIBS $LIBS -lz"
CFLAGS="$LIBGCRYPT_CFLAGS $GNUTLS_CFLAGS $CFLAGS"

dnl Outputting the necessary files for the build.
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT(Makefile)
