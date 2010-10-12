#! /bin/sh

mkdir -p src/autogen
set -x
aclocal -I project
libtoolize
autoheader
automake --foreign --add-missing --copy
autoconf
