#!/bin/sh

# Copyright (C) 2014  Sergio Durigan Junior <sergiodj@sergiodj.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# These are the necessary steps to generate the configure scripts.

set -x

# Use "build-aux" as our aux dir, i.e., put the generated files there.
AUX_DIR=build-aux

test -d $AUX_DIR || mkdir -p $AUX_DIR

aclocal
autoheader
autoconf
automake --add-missing --copy --force --foreign
