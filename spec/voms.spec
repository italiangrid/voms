Name: voms
Version: 2.0.7
Release: 1%{?dist}
Summary: The Virtual Organisation Membership Service C++ APIs

Group:          System Environment/Libraries
License:        ASL 2.0
URL: https://twiki.cnaf.infn.it/twiki/bin/view/VOMS
Source: %{name}-%{version}.tar.gz

BuildRequires: libtool
BuildRequires: expat-devel
BuildRequires: openssl-devel
BuildRequires:  pkgconfig

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

%prep
%setup -q
# Touch to avoid rerunning bison and flex
touch -r src/utils/vomsfake.y src/utils/vomsparser.h
touch -r src/utils/vomsfake.y src/utils/vomsparser.c
touch -r src/utils/vomsfake.y src/utils/lex.yy.c

./autogen.sh

%build

%configure --libexecdir=%{_datadir} --sysconfdir=%{_datadir} \
	--disable-static --disable-docs --with-api-only


make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm $RPM_BUILD_ROOT%{_libdir}/*.la
rm $RPM_BUILD_ROOT%{_mandir}/man8/voms-install-replica.8
rm $RPM_BUILD_ROOT%{_mandir}/man3/data.3*

%clean

rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

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

%changelog
