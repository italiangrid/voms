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
rm -f $dir/usr/lib/*.a
rm -f $dir/usr/lib/*.la
rm -f $dir/usr/lib/*_gcc*.so.*
rm -f $dir/usr/lib/*.so.*
rm -f $dir/usr/lib64/*.a
rm -f $dir/usr/lib64/*.la
rm -f $dir/usr/lib64/*_gcc*.so.*
rm -f $dir/usr/lib64/*.so.*

#mv $dir/usr/include/glite/security/voms $dir/usr/include/voms
mv $dir/include/glite/security/voms $dir/usr/include/voms
rm -rf $dir/include/glite

mv $dir/usr/share/mv $dir/usr/share/aclocal

#touch $dir/etc/vomses
rm -rf $dir/etc/
#rm -rf $dir/include
rm -rf $dir/usr/bin
rm -rf $dir/usr/sbin
rm -rf $dir/var
rm -rf $dir/libexec
rm -rf $dir/share

mkdir -p $dir/usr/share/voms-devel-$version
install -m 644 -p LICENSE AUTHORS $dir/usr/share/voms-devel-$version
fi
