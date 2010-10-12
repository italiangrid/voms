#!/bin/sh

dir=$1
action=$2
version=$3

if test "x$action" = "xpre"; then
# Fix bad permissions (which otherwise end up in the debuginfo package)
find . '(' -name '*.h' -o -name '*.c' -o -name '*.cpp' -o \
	   -name '*.cc' -o -name '*.java' ')' -exec chmod a-x {} ';'

# Fix location dir
sed -e 's/\(LOCATION_DIR.*\)"\$prefix"/\1""/g' -i project/acinclude.m4

# Fix default Globus location
sed -e 's!\(GLOBUS_LOCATION\)!{\1:-/usr}!' -i project/voms.m4

# Fix default vomses file location
sed -e 's!/opt/glite/etc/vomses!/etc/vomses!' -i src/api/ccapi/voms_api.cc

# Use pdflatex
sed -e 's!^\(USE_PDFLATEX *= *\)NO!\1YES!' -i src/api/ccapi/Makefile.am

# Touch to avoid rerunning bison and flex
touch -r src/utils/vomsfake.y src/utils/vomsparser.h
touch -r src/utils/vomsfake.y src/utils/vomsparser.c
touch -r src/utils/vomsfake.y src/utils/lex.yy.c

# rebootstrap
./autogen.sh
fi

if test "x$action" = "xport"; then
rm -f $dir/usr/bin/edg-voms*
rm -f $dir/usr/sbin/edg-voms*

rm -f $dir/usr/lib/*.a
rm -f $dir/usr/lib/*.la

rm $dir/usr/share/vomses.template

mkdir -p $dir/etc/grid-security/vomsdir
mkdir -p $dir/etc/grid-security/voms
mkdir -p $dir/etc/voms
mkdir -p $dir/var/log/voms

#touch $dir/etc/vomses
rm -f $dir/etc/vomses

sed -e 's!${datapath}/etc/voms/voms!${basepath}/share/voms/voms!' \
    -e 's/useradd/\#&/' -e 's/groupadd/\#&/' \
    -e 's/vomsd(8)/voms(8)/' \
    -i $dir/usr/share/voms/voms_install_db

cat >> $dir/usr/share/voms/voms_install_db << EOF
\$ECHO -en "--x509_user_cert=/etc/grid-security/voms/hostcert.pem\n" >> \$datapath/etc/voms/\$voms_vo/voms.conf
\$ECHO -en "--x509_user_key=/etc/grid-security/voms/hostkey.pem\n" >> \$datapath/etc/voms/\$voms_vo/voms.conf
EOF

# Turn off default enabling of the service
mkdir -p $dir/etc/rc.d/init.d
sed -e 's/\(chkconfig: \)\w*/\1-/' \
    -e '/Default-Start/d' \
    -e 's/\(Default-Stop:\s*\).*/\10 1 2 3 4 5 6/' \
   $dir/usr/share/init.d/voms > \
   $dir/etc/rc.d/init.d/voms
chmod 755 $dir/etc/rc.d/init.d/voms
rm -rf $dir/usr/share/init.d

mkdir -p $dir/etc/sysconfig
echo VOMS_USER=voms > $dir/etc/sysconfig/voms

mkdir -p $dir/usr/share/voms-server-$version
install -m 644 -p LICENSE AUTHORS $dir/usr/share/voms-server-$version

fi
