Name: voms-clients
Version: 2.0.8
Release: 1%{?dist}

Summary:	Virtual Organization Membership Service Clients

Group:		Applications/Internet
Requires:	voms%{?_isa} = %{version}-%{release}
License:        ASL 2.0
URL: https://twiki.cnaf.infn.it/twiki/bin/view/VOMS
Source: voms-%{version}.tar.gz

BuildRequires: libtool
BuildRequires: expat-devel
BuildRequires: pkgconfig
BuildRequires: openssl-devel%{?_isa}
BuildRequires: libxslt
BuildRequires: docbook-style-xsl
BuildRequires: doxygen
BuildRequires: bison

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Packager: Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it>

%description
The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for
authorization purposes.

This package provides command line applications to access the VOMS
services.

%prep
%setup -q -n voms-%{version}
./autogen.sh

%build

%configure --disable-static --enable-docs --disable-parser-gen \
	--without-all --with-clients --with-config

make %{?_smp_mflags}

%install

rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm $RPM_BUILD_ROOT%{_datadir}/voms/*
rm $RPM_BUILD_ROOT%{_mandir}/man3/*.3*

%clean

rm -rf $RPM_BUILD_ROOT

%files
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

%changelog

* Tue Apr 10 2011 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.8-1
- EMI 2 release.

* Thu Dec 15 2011 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.7-1
- Restructured EMI build to leverage EPEL spec files by Mattias Ellert
- Removed voms-java-apis from the main c-based source tree  
