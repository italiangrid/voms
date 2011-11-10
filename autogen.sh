#! /bin/sh

mkdir -p src/autogen
set -x
aclocal -I project
glibtoolize --force
autoheader
automake --foreign --add-missing --copy
autoconf
