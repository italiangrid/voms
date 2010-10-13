#!/bin/sh
dir=$1
action=$2
version=$3

if test "x$action" = "xpre"; then
# Use pdflatex
sed -e 's!^\(USE_PDFLATEX *= *\)NO!\1YES!' -i src/api/ccapi/Makefile.am

# Touch to avoid rerunning bison and flex
touch -r src/utils/vomsfake.y src/utils/vomsparser.h
touch -r src/utils/vomsfake.y src/utils/vomsparser.c
touch -r src/utils/vomsfake.y src/utils/lex.yy.c

# rebootstrap
./autogen.sh
fi

if test "x$action" = "xpost"; then
rm -f $dir/usr/bin/edg-voms*
rm -f $dir/usr/sbin/edg-voms*

rm -f $dir/usr/lib/*.a
rm -f $dir/usr/lib/*.la
rm -f $dir/usr/lib/*_gcc*.so.*
rm -f $dir/usr/lib/*.so.*

mv $dir/usr/include/glite/security/voms $dir/usr/include/voms
rm -rf $dir/usr/include/glite

mv $dir/usr/share/mv $dir/usr/share/aclocal

mkdir -p $dir/etc/grid-security/vomsdir
mkdir -p $dir/etc/grid-security/voms
mkdir -p $dir/etc/voms
mkdir -p $dir/var/log/voms

#touch $dir/etc/vomses
rm -f $dir/etc/vomses
rm -rf $dir/include
rm -rf $dir/usr/include
rm -rf $dir/lib
rm -rf $dir/lib64
rm -rf $dir/usr/include

mkdir -p $dir/usr/share/voms-devel-$version
install -m 644 -p LICENSE AUTHORS $dir/usr/share/voms-devel-$version
fi
