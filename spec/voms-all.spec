Name: voms
Version: 2.1.1
Release: 0%{?dist}
Summary: The Virtual Organisation Membership Service C++ APIs

Group:          System Environment/Libraries
License:        ASL 2.0
URL: https://twiki.cnaf.infn.it/twiki/bin/view/VOMS
Source: %{name}-%{version}.tar.gz

BuildRequires: libtool
BuildRequires: expat-devel
BuildRequires: pkgconfig
BuildRequires: openssl-devel%{?_isa}
BuildRequires: gsoap-devel
BuildRequires: libxslt
BuildRequires: docbook-style-xsl
BuildRequires: doxygen
BuildRequires: bison

Requires: expat
Requires: openssl

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Packager: Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it>

%description
The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for
authorization purposes.

This package provides libraries that applications using the VOMS functionality
will bind to.

%package devel
Summary:	Virtual Organization Membership Service Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	openssl-devel%{?_isa}
Requires:	automake

%description devel
The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for
authorization purposes.

This package provides header files for programming with the VOMS libraries.

%package doc
Summary:	Virtual Organization Membership Service Documentation
Group:		Documentation
%if %{?fedora}%{!?fedora:0} >= 10 || %{?rhel}%{!?rhel:0} >= 6
BuildArch:	noarch
%endif
Requires:	%{name} = %{version}-%{release}

%description doc
Documentation for the Virtual Organization Membership Service.

%package clients
Summary:	Virtual Organization Membership Service Clients
Group:		Applications/Internet

Requires:	%{name}%{?_isa} = %{version}-%{release}
Conflicts: voms-clients3 <= 3.0.4

Requires(post):         %{_sbindir}/update-alternatives
Requires(postun):       %{_sbindir}/update-alternatives

%description clients
The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for
authorization purposes.

This package provides command line applications to access the VOMS
services.

%package server
Summary:	Virtual Organization Membership Service Server
Group:		Applications/Internet
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	gsoap

Requires(pre):		shadow-utils
Requires(post):		chkconfig
Requires(preun):	chkconfig
Requires(preun):	initscripts
Requires(postun):	initscripts

%description server
The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for
authorization purposes.

This package provides the VOMS service.

%prep
%setup -q

# Fix bad permissions (which otherwise end up in the debuginfo package)
find . '(' -name '*.h' -o -name '*.c' -o -name '*.cpp' -o \
        -name '*.cc' -o -name '*.java' ')' -exec chmod a-x {} ';'
./autogen.sh

%build

%configure --disable-static --enable-docs --disable-parser-gen

make %{?_smp_mflags}

%install

rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm $RPM_BUILD_ROOT%{_libdir}/*.la

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/grid-security/vomsdir
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/grid-security/%{name}
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/log/%{name}
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/%{name}

mkdir -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}
install -m 644 -p LICENSE AUTHORS $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}

## C API documentation
mkdir -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/VOMS_C_API
cp -pr  doc/apidoc/api/VOMS_C_API/html \
	$RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/VOMS_C_API
rm -f $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/VOMS_C_API/html/installdox

mkdir -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/VOMS_CC_API
cp -pr  doc/apidoc/api/VOMS_CC_API/html \
	$RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/VOMS_CC_API
rm -f $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/VOMS_CC_API/html/installdox

for b in voms-proxy-init voms-proxy-info voms-proxy-destroy; do
  ## Rename client binaries 
  mv $RPM_BUILD_ROOT%{_bindir}/${b} $RPM_BUILD_ROOT%{_bindir}/${b}2

  ## and man pages
  mv $RPM_BUILD_ROOT%{_mandir}/man1/${b}.1 $RPM_BUILD_ROOT%{_mandir}/man1/${b}2.1

  # Needed by alternatives. See http://fedoraproject.org/wiki/Packaging:Alternatives
  touch $RPM_BUILD_ROOT/%{_bindir}/${b}
done

%clean

rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%posttrans
# Recover /etc/vomses...
if [ -r %{_sysconfdir}/vomses.rpmsave -a ! -r %{_sysconfdir}/vomses ] ; then
   mv %{_sysconfdir}/vomses.rpmsave %{_sysconfdir}/vomses
fi

%pre server
getent group %{name} >/dev/null || groupadd -r %{name}
getent passwd %{name} >/dev/null || useradd -r -g %{name} \
    -d %{_sysconfdir}/%{name} -s /sbin/nologin -c "VOMS Server Account" %{name}
exit 0

%post server
/sbin/chkconfig --add %{name}

if [ $1 -eq 2 ]; then
    chown -R %{name} /var/log/voms
    chown -R %{name} /etc/voms
fi

%preun server
if [ $1 = 0 ]; then
    /sbin/service %{name} stop >/dev/null 2>&1 || :
    /sbin/chkconfig --del %{name}
fi

%postun server
if [ $1 -ge 1 ]; then
    /sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi

%pre clients

if [ $1 -eq 2 ]; then 
  for c in voms-proxy-init voms-proxy-info voms-proxy-destroy; do
    if [[ -x %{_bindir}/$c && ! -L %{_bindir}/$c ]]; then
      rm -f %{_bindir}/$c
    fi
  done
fi

%post clients

%{_sbindir}/update-alternatives --install %{_bindir}/voms-proxy-init \
    voms-proxy-init %{_bindir}/voms-proxy-init2 50 \
    --slave %{_mandir}/man1/voms-proxy-init.1.gz voms-proxy-init-man %{_mandir}/man1/voms-proxy-init2.1.gz 

%{_sbindir}/update-alternatives --install %{_bindir}/voms-proxy-info \
    voms-proxy-info %{_bindir}/voms-proxy-info2 50 \
    --slave %{_mandir}/man1/voms-proxy-info.1.gz voms-proxy-info-man %{_mandir}/man1/voms-proxy-info2.1.gz

%{_sbindir}/update-alternatives --install %{_bindir}/voms-proxy-destroy \
    voms-proxy-destroy %{_bindir}/voms-proxy-destroy2 50 \
    --slave %{_mandir}/man1/voms-proxy-destroy.1.gz voms-proxy-destroy-man %{_mandir}/man1/voms-proxy-destroy2.1.gz

%postun clients

if [ $1 -eq 0 ] ; then
  %{_sbindir}/update-alternatives  --remove voms-proxy-init %{_bindir}/voms-proxy-init2
  %{_sbindir}/update-alternatives  --remove voms-proxy-info %{_bindir}/voms-proxy-info2
  %{_sbindir}/update-alternatives  --remove voms-proxy-destroy %{_bindir}/voms-proxy-destroy2
fi

%files
%defattr(-,root,root,-)
%{_libdir}/libvomsapi.so.1*
%dir %{_sysconfdir}/grid-security
%dir %{_sysconfdir}/grid-security/vomsdir
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/vomses.template
%doc %dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/AUTHORS
%doc %{_docdir}/%{name}-%{version}/LICENSE

%files devel
%defattr(-,root,root,-)
%{_libdir}/libvomsapi.so
%{_includedir}/%{name}
%{_libdir}/pkgconfig/%{name}-2.0.pc
%{_datadir}/aclocal/%{name}.m4
%{_mandir}/man3/*

%files doc
%defattr(-,root,root,-)
%doc %{_docdir}/%{name}-%{version}/VOMS_C_API
%doc %{_docdir}/%{name}-%{version}/VOMS_CC_API

%files clients
%defattr(-,root,root,-)

%ghost %{_bindir}/voms-proxy-destroy
%ghost %{_bindir}/voms-proxy-info
%ghost %{_bindir}/voms-proxy-init

%{_bindir}/voms-proxy-destroy2
%{_bindir}/voms-proxy-info2
%{_bindir}/voms-proxy-init2
%{_bindir}/voms-proxy-fake
%{_bindir}/voms-proxy-list
%{_bindir}/voms-verify

%{_mandir}/man1/voms-proxy-destroy2.1.gz
%{_mandir}/man1/voms-proxy-info2.1.gz
%{_mandir}/man1/voms-proxy-init2.1.gz
%{_mandir}/man1/voms-proxy-fake.1.gz
%{_mandir}/man1/voms-proxy-list.1.gz

%files server
%defattr(-,root,root,-)
%{_sbindir}/%{name}
%{_initrddir}/%{name}
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/grid-security/%{name}
%attr(-,voms,voms) %dir %{_localstatedir}/log/%{name}
%{_datadir}/%{name}/mysql2oracle
%{_datadir}/%{name}/upgrade1to2
%{_datadir}/%{name}/voms.data
%{_datadir}/%{name}/voms_install_db
%{_datadir}/%{name}/voms-ping
%{_datadir}/%{name}/voms_replica_master_setup.sh
%{_datadir}/%{name}/voms_replica_slave_setup.sh
%{_mandir}/man8/voms.8*

%changelog
* Tue Aug 23 2016 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.1.0-0
- Packaging for 2.1.0

* Tue Aug 23 2016 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.14-0
- Packaging for 2.0.14

* Mon Nov 9 2015 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.13-0
- Packaging for 2.0.13

* Mon May 12 2014 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.12-2
- Added missing dependency on gsoap.

* Mon May 12 2014 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.12-1
- New packaging of the clients. https://issues.infn.it/jira/browse/VOMS-495

* Mon Aug 21 2013 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.11-1
- Fix for https://issues.infn.it/browse/VOMS-379

* Tue Jan 8 2013 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.10-1
- Fix for https://issues.infn.it/browse/VOMS-196

* Sat Oct 27 2012 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.9-1
- Fix for https://savannah.cern.ch/bugs/?91183
- Fix for http://issues.cnaf.infn.it/browse/VOMS-128

* Tue Apr 10 2012 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.8-1
- EMI 2 release.

* Thu Dec 15 2011 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.7-1
- Restructured EMI build to leverage EPEL spec files by Mattias Ellert
- Removed voms-java-apis from the main c-based source tree  
