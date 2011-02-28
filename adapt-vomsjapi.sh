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
mv $dir/usr/share/java/vomsjapi.jar $dir/usr/share/java/vomsjapi-$version.jar
cd $dir/usr/share/java
ln -s vomsjapi-$version.jar vomsjapi.jar
cd -
rm -rf $dir/usr/share/man

mkdir -p $dir/usr/share/doc/vomsjapi-$version
install -m 644 -p LICENSE AUTHORS $dir/usr/share/doc/vomsjapi-$version

fi
