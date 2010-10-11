%global with_gcj %{!?_without_gcj:1}%{?_without_gcj:0}

Name:		voms-server
Version:	2.0.0
Release:	1%{?dist}
Summary:	Virtual Organization Membership Service

Group:		Applications/Internet
License:	ASL 2.0
URL:		http://glite.web.cern.ch/glite/
#		The source tarball is created from a CVS checkout:
#		cvs -d:pserver:anonymous:@glite.cvs.cern.ch:/cvs/glite co \
#		  -r glite-security-voms_R_1_9_17_1 \
#		  -d voms-1.9.17.1 org.glite.security.voms
#		tar -z -c --exclude CVS -f voms-1.9.17.1.tar.gz voms-1.9.17.1
Source:		%{name}-%{version}.tar.gz
#		Post-install setup instructions:
#Source1:	%{name}.INSTALL
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	openssl-devel%{?_isa}
BuildRequires:	expat-devel
BuildRequires:	libtool
BuildRequires:	pkgconfig
Requires:	%{name}%{?_isa} = %{version}-%{release}

Requires(pre):		shadow-utils
Requires(post):		chkconfig
Requires(preun):	chkconfig
Requires(preun):	initscripts
Requires(postun):	initscripts

%description
In grid computing, and whenever the access to resources may be controlled
by parties external to the resource provider, users may be grouped to
Virtual Organizations (VOs). This package provides a VO Membership Service
(VOMS), which informs on that association between users and their VOs:
groups, roles and capabilities.

The service can be understood as an account database, which serves the
information in a special format (VOMS credential). The VO manager can
administrate it remotely using command line tools or a web interface.


%prep
%setup -q

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

#install -m 644 %{SOURCE1} INSTALL.Fedora

%build
%configure --with-all=no --enable-java=no --with-config=yes --with-server=yes \
      --disable-glite --libexecdir=%{_datadir} --sysconfdir=%{_datadir}

make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm -f $RPM_BUILD_ROOT%{_bindir}/edg-voms*
rm -f $RPM_BUILD_ROOT%{_sbindir}/edg-voms*
rm -f $RPM_BUILD_ROOT%{_mandir}/man1/edg-voms*
rm -f $RPM_BUILD_ROOT%{_mandir}/man8/edg-voms*
rm -f $RPM_BUILD_ROOT%{_mandir}/man1/glite-voms*
rm -f $RPM_BUILD_ROOT%{_mandir}/man8/glite-voms*

rm -f $RPM_BUILD_ROOT%{_libdir}/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la

#mv $RPM_BUILD_ROOT%{_includedir}/glite/security/%{name} \
#   $RPM_BUILD_ROOT%{_includedir}/%{name}
#rm -rf $RPM_BUILD_ROOT%{_includedir}/glite

rm $RPM_BUILD_ROOT%{_datadir}/vomses.template

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/grid-security/vomsdir
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/grid-security/voms
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/voms
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/log/voms

#touch $RPM_BUILD_ROOT%{_sysconfdir}/vomses
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/vomses

sed -e 's!${datapath}/etc/voms/voms!${basepath}/share/voms/voms!' \
    -e 's/useradd/\#&/' -e 's/groupadd/\#&/' \
    -e 's/vomsd(8)/voms(8)/' \
    -i $RPM_BUILD_ROOT%{_datadir}/voms/voms_install_db

cat >> $RPM_BUILD_ROOT%{_datadir}/voms/voms_install_db << EOF
\$ECHO -en "--x509_user_cert=/etc/grid-security/voms/hostcert.pem\n" >> \$datapath/etc/voms/\$voms_vo/voms.conf
\$ECHO -en "--x509_user_key=/etc/grid-security/voms/hostkey.pem\n" >> \$datapath/etc/voms/\$voms_vo/voms.conf
EOF

# Turn off default enabling of the service
mkdir -p $RPM_BUILD_ROOT%{_initrddir}
sed -e 's/\(chkconfig: \)\w*/\1-/' \
    -e '/Default-Start/d' \
    -e 's/\(Default-Stop:\s*\).*/\10 1 2 3 4 5 6/' \
   $RPM_BUILD_ROOT%{_datadir}/init.d/voms > \
   $RPM_BUILD_ROOT%{_initrddir}/voms
chmod 755 $RPM_BUILD_ROOT%{_initrddir}/voms
rm -rf $RPM_BUILD_ROOT%{_datadir}/init.d

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
echo VOMS_USER=voms > $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/voms

mkdir -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}
install -m 644 -p LICENSE AUTHORS $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}

%clean
rm -rf $RPM_BUILD_ROOT

%pre
getent group voms >/dev/null || groupadd -r voms
getent passwd voms >/dev/null || useradd -r -g voms \
    -d %{_sysconfdir}/voms -s /sbin/nologin -c "VOMS Server Account" voms
exit 0

%post -p /sbin/ldconfig
if [ $1 = 1 ]; then
    /sbin/chkconfig --add voms
fi

%preun
if [ $1 = 0 ]; then
    /sbin/service %{name} stop >/dev/null 2>&1 || :
    /sbin/chkconfig --del voms
fi

%postun -p /sbin/ldconfig
if [ $1 -ge 1 ]; then
    /sbin/service voms condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root,-)
%{_sbindir}/voms
%{_initrddir}/voms
%config(noreplace) %{_sysconfdir}/sysconfig/voms
%dir %{_sysconfdir}/voms
%dir %{_sysconfdir}/grid-security/voms
%attr(-,voms,voms) %dir %{_localstatedir}/log/voms
%{_datadir}/voms/mysql2oracle
%{_datadir}/voms/upgrade1to2
%{_datadir}/voms/voms.data
%{_datadir}/voms/voms_install_db
%{_datadir}/voms/voms-ping
%{_datadir}/voms/voms_replica_master_setup.sh
%{_datadir}/voms/voms_replica_slave_setup.sh
%{_mandir}/man8/voms*8*
%{_docdir}/%{name}-%{version}/AUTHORS
%{_docdir}/%{name}-%{version}/LICENSE
#%doc INSTALL.Fedora

%changelog
* Tue Sep 28 2010 Vincenzo Ciaschini <vincenzo.ciaschini@cnaf.infn.it> - 2.0.0
- Split into separate spec files.  This is the server specfile

* Thu Jul 08 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.17.1-2
- Make -doc subpackage depend of main package for license reasons

* Sat Jun 05 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.17.1-1
- Upstream 1.9.17.1 (CVS tag glite-security-voms_R_1_9_17_1)
- Drop patches voms-db-method.patch and voms-thread.patch (accepted upstream)

* Sun Mar 28 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.16.1-2
- Add mutex lock for accessing private data

* Fri Mar 19 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.16.1-1
- Upstream 1.9.16.1 (CVS tag glite-security-voms_R_1_9_16_1)
- Fix uninitialized variable in voms-proxy-init

* Mon Dec 28 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.14.3-1
- Upstream 1.9.14.3 (CVS tag glite-security-voms_R_1_9_14_3)
- Add missing dependencies for stricter binutils

* Tue Oct 20 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.14.2-1
- Upstream 1.9.14.2 (CVS tag glite-security-voms_R_1_9_14_2)

* Fri Sep 18 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.12.1-1
- Upstream 1.9.12.1 (CVS tag glite-security-voms_R_1_9_12_1)

* Mon Sep 07 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.11-4
- Fix building with openssl 1.0

* Thu Sep 03 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.11-3
- Add an empty /etc/vomses file to the main package to avoid error messages
- Let the voms user own only necessary directories
- Additional fixes for the server start-up script

* Tue Aug 25 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.11-2
- Add the /etc/voms directory to the server package
- Add setup instructions to the server package
- Run the server as non-root

* Fri Aug 14 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.11-1
- Upstream 1.9.11 (CVS tag glite-security-voms_R_1_9_11)
- Enable Java AOT bits

* Mon Jun 29 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.8.1-1
- Upstream 1.9.8.1 (CVS tag glite-security-voms_R_1_9_8_1)
- Build Java API

* Thu Feb 12 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.2-1
- Upstream 1.9.2 (CVS tag glite-security-voms_R_1_9_2)

* Fri Feb 06 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.9.1-1
- Upstream 1.9.1 (CVS tag glite-security-voms_R_1_9_1)

* Tue Jan 06 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.8.10-1
- Upstream 1.8.10 (CVS tag glite-security-voms_R_1_8_10)
- Rebuild against distribution Globus
- Add clear SSL error patch needed for openssl > 0.9.8b
- Add missing return value patch

* Sun Oct 26 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.8.9-1ng
- Upstream 1.8.9 (CVS tag glite-security-voms_R_1_8_9)
- Rebuild against Globus 4.0.8-0.11

* Thu May 15 2008 Anders Wäänänen <waananen@nbi.dk> - 1.7.24-4ng
- Add missing include patch

* Sat Apr 26 2008 Anders Wäänänen <waananen@nbi.dk> - 1.7.24-3ng
- Rebuild against Globus 4.0.7-0.10

* Sun Nov 25 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.24-2ng
- Fix GPT_LOCATION and GLOBUS_LOCATION detection in spec file

* Mon Oct 29 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.24-1ng
- Upstream 1.7.24 (CVS tag glite-security-voms_R_1_7_24_1)

* Mon Oct 15 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.23-1ng
- Upstream 1.7.23 (CVS tag glite-security-voms_R_1_7_23_1)

* Wed Sep 12 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.22-3ng
- Move /etc/voms/vomses back to /etc/vomses
- Added more openssl portability patches with input
  from Aake Sandgren <ake.sandgren@hpc2n.umu.se>

* Wed Sep 12 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.22-2ng
- Added more openssl portability patches with input
  from Aake Sandgren <ake.sandgren@hpc2n.umu.se>

* Mon Sep 10 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.22-1ng
- Try to link against system crypto library when Globus library is not
  available
- Make /etc/grid-security/vomsdir part of the voms sub-package
- Drop RPM prefix /etc
- Move the vomses.template to /etc/voms
- Use dashes instead of underscore in voms-install-replica.1 man page
- Do not try to link against system crypt library. Voms now
  does this internally.
- Upstream 1.7.22 (CVS tag glite-security-voms_R_1_7_22_1)

* Mon Jul 16 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.20-5ng
- Drop voms-struct_change.patch - problem is with libxml2

* Sat Jul 14 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.20-4ng
- Add missing openssl-devel dependency in voms-devel

* Thu Jul 12 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.20-3ng
- Add patch:
  - voms-struct_change.patch
    - Change API slightly - but now works with libxml2

* Thu Jul 08 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.20-2ng
- Make conditinal dependency on expat-devel (OpenSuSE 10.20 has only expat)

* Thu Jul 05 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.20-1ng
- Upstream 1.7.20 (CVS tag glite-security-voms_R_1_7_20_1) 

* Thu Jul 05 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.19-2ng
- Added patches:
  - voms-openssl_portability.patch
    - Support for newer OpenSSL-0.9.8
  - voms-isoc90_portability.patch
    - Support for older compilers
- Added openssl-devel build dependency

* Fri Jun 22 2007 Anders Wäänänen <waananen@nbi.dk> - 1.7.19-1ng
- Upstream 1.7.19 (CVS tag glite-security-voms_R_1_7_19_P2) 
- Remove patches (use shell substitutions instead)
- Disable Java API build

* Fri Jun 22 2007 Anders Wäänänen <waananen@nbi.dk> - 1.6.20-3ng
- Added Globus dependencies to voms-devel

* Mon Jul 24 2006 Anders Wäänänen <waananen@nbi.dk> - 1.6.20-2ng
- Fix dependency typo: Requires -> BuildRequires

* Sat May 06 2006 Anders Wäänänen <waananen@nbi.dk> - 1.6.20-1ng
- Many changes since upstream changed quite a lot.
- Added README.NorduGrid with packaging information
- Patches:
  - voms_openssl-0.9.8.patch
    - Support for OpenSSL 0.9.8
  - voms_noglobusopenssl-1.6.20.patch
    - Use system openssl rather than the one from Globus
    - Patch reworked for voms 1.6.20
  - Dont use project based (gLite) include paths
- Pseudo patches (fixes made at runtime and not from static patch files)
  - Fix broken --libexecdir support for configure
    (some systems do not have libexecdir = <prefix>/libexec)
  - Drop all documents except man pages which are pre-generated
    (section 3 man pages are skipped as well)
  - Do not use edg- prefix
    (can be turned on/off through macro)
  - Install flavored libraries in addition to non-flavored
    (can be turned on/off through macro)
  - Put start-up script in /etc/init.d
  - Move configuration files from <prefix>/etc to /etc

* Mon Dec 19 2005 Anders Wäänänen <waananen@nbi.dk> - 1.6.9-2
- Add patch voms_doc.patch to disable html and ps documentation
  and add man-mages and pdf files to distribution (make dist)
- Use rpm switch: --define "_autotools_bootstrap 1" to rebuild
  documentation and create "make dist" target
- Add patch voms_nohardcodelibexecdir.patch which use the libexecdir
  from configure rather than the hardcoded prefix/libexec

* Sun Nov 27 2005 Anders Wäänänen <waananen@nbi.dk> - 1.6.9-1
- Add patch voms_ssl_include.patch to add external openssl includes.
  Would be better to query globus_openssl about this

* Tue Oct 18 2005 Anders Wäänänen <waananen@nbi.dk> - 1.6.7-1
- Modfiy voms_noglobusopenssl.patch to match upstream
- Add patch voms_nops.patch to disable postscript versions of
  reference manual

* Fri Jun 17 2005 Anders Wäänänen <waananen@nbi.dk> - 1.5.4-1
- Remove the following patches:
  - voms_namespace.patch - Fixed in upstream
  - voms_external_mysql++-1.4.1.patch - Obsolete since mysql++ is no
    longer needed
  - voms-no_libs.path - Fixed in upstream
- Add Globus dependencies

* Wed Jun 01 2005 Anders Wäänänen <waananen@nbi.dk> - 1.4.1-3
- Do not hardcode Globus flavor but try to guess
- Remove explicit globus rpm Requirement
- Use external openssl - not globus_openssl

* Mon May 02 2005 Anders Wäänänen <waananen@nbi.dk> - 1.4.1-2
- Remove automake cache
- Add explicit dependency on mysql++-devel

* Sat Apr 30 2005 Anders Wäänänen <waananen@nbi.dk> - 1.4.1-1
- New upstream
- autogen.sh -> autobuild.sh

* Mon Apr 18 2005 Anders Wäänänen <waananen@nbi.dk> - 1.3.2-1
- Initial build.
