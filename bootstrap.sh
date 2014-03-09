#!/bin/sh

# These are the necessary steps to generate the configure scripts.

set -x

# Use "build-aux" as our aux dir, i.e., put the generated files there.
AUX_DIR=build-aux

test -d $AUX_DIR || mkdir -p $AUX_DIR

aclocal
autoconf
automake --add-missing --copy --force --foreign
