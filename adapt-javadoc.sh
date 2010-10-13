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

mkdir javadoc
cd javadoc
javadoc ../src/api/java/org/glite/voms/*.java \
	../src/api/java/org/glite/voms/ac/*.java \
	../src/api/java/org/glite/voms/contact/*.java
cd ..

mkdir -p $dir/usr/share/javadoc
cp -pr javadoc $dir/usr/share/javadoc/vomsjapi-$version
ln -s vomsjapi-$version $dir/usr/share/javadoc}/vomsjapi-$version

mkdir -p $dir/usr/share/vomsjapi-javadoc-$version
install -m 644 -p LICENSE AUTHORS $dir/usr/share/vomsjapi-javadoc-$version

fi
