Name: voms
Version: 2.0.8
Release: 1%{?dist}
Summary: The Virtual Organisation Membership Service C++ APIs

Group:          System Environment/Libraries
License:        ASL 2.0
URL: https://twiki.cnaf.infn.it/twiki/bin/view/VOMS
Source: %{name}-%{version}.tar.gz

BuildRequires: libtool
BuildRequires: expat-devel
BuildRequires: pkgconfig
BuildRequires: openssl-devel%{?_isa}
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
if [ $1 = 1 ]; then
    /sbin/chkconfig --add %{name}
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
%{_bindir}/voms-proxy-destroy
%{_bindir}/voms-proxy-info
%{_bindir}/voms-proxy-init
%{_bindir}/voms-proxy-fake
%{_bindir}/voms-proxy-list
%{_mandir}/man1/voms-proxy-destroy.1*
%{_mandir}/man1/voms-proxy-info.1*
%{_mandir}/man1/voms-proxy-init.1*
%{_mandir}/man1/voms-proxy-fake.1*
%{_mandir}/man1/voms-proxy-list.1*

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

* Tue Apr 10 2011 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.8-1
- EMI 2 release.

* Thu Dec 15 2011 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.7-1
- Restructured EMI build to leverage EPEL spec files by Mattias Ellert
- Removed voms-java-apis from the main c-based source tree  
