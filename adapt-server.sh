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

rm -f $dir/usr/lib/
rm -f $dir/usr/lib64/

rm $dir/usr/share/vomses.template

mkdir -p $dir/etc/grid-security/vomsdir
mkdir -p $dir/etc/grid-security/voms
mkdir -p $dir/etc/voms
mkdir -p $dir/var/log/voms

#touch $dir/etc/vomses
rm -f $dir/etc/vomses
rm -rf $dir/include
rm -rf $dir/lib
rm -rf $dir/lib64
rm -rf $dir/usr/lib
rm -rf $dir/usr/lib64
rm -rf $dir/usr/include

sed -e 's!${datapath}/etc/voms/voms!${basepath}/share/voms/voms!' \
    -e 's/useradd/\#&/' -e 's/groupadd/\#&/' \
    -e 's/vomsd(8)/voms(8)/' \
    -i $dir/usr/libexec/voms/voms_install_db

# Turn off default enabling of the service
mkdir -p $dir/etc/rc.d/init.d
sed -e 's/\(chkconfig: \)\w*/\1-/' \
    -e '/Default-Start/d' \
    -e 's/\(Default-Stop:\s*\).*/\10 1 2 3 4 5 6/' \
   $dir/etc/init.d/voms > \
   $dir/etc/rc.d/init.d/voms
chmod 755 $dir/etc/rc.d/init.d/voms
rm -rf $dir/usr/share/init.d
rm -rf $dir/etc/init.d

mkdir -p $dir/etc/sysconfig
echo VOMS_USER=voms > $dir/etc/sysconfig/voms

mkdir -p $dir/usr/share/voms-server-$version
install -m 644 -p LICENSE AUTHORS $dir/usr/share/voms-server-$version

fi
