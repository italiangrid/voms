Name: voms-devel
Version: 2.0.8
Release: 1%{?dist}

Summary:	Virtual Organization Membership Service Development Files

Group:		Development/Libraries
License:        ASL 2.0

BuildRequires: libtool
BuildRequires: expat-devel
BuildRequires: pkgconfig
BuildRequires: openssl-devel%{?_isa}
BuildRequires: libxslt
BuildRequires: docbook-style-xsl
BuildRequires: doxygen
BuildRequires: bison

Requires:   	expat
Requires:   	openssl
Requires:	voms%{?_isa} = %{version}-%{release}
Requires:	openssl-devel%{?_isa}
Requires:	automake

Summary: The Virtual Organisation Membership Service C++ APIs (Development files)

Group: System Environment/Libraries

URL: https://twiki.cnaf.infn.it/twiki/bin/view/VOMS

Source: voms-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Packager: Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it>

%description
The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for
authorization purposes.

%prep
%setup -q -n voms-%{version}

# Fix bad permissions (which otherwise end up in the debuginfo package)
find . '(' -name '*.h' -o -name '*.c' -o -name '*.cpp' -o \
        -name '*.cc' -o -name '*.java' ')' -exec chmod a-x {} ';'
./autogen.sh

%build

%configure --enable-docs --disable-static --disable-parser-gen --with-api-only
	

make %{?_smp_mflags}

%install

rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm $RPM_BUILD_ROOT%{_libdir}/*.la
rm $RPM_BUILD_ROOT%{_mandir}/man8/*.8
rm $RPM_BUILD_ROOT%{_mandir}/man1/*.1
rm $RPM_BUILD_ROOT%{_libdir}/libvomsapi.so.1*

%clean

rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%posttrans
# Recover /etc/vomses...
if [ -r %{_sysconfdir}/vomses.rpmsave -a ! -r %{_sysconfdir}/vomses ] ; then
   mv %{_sysconfdir}/vomses.rpmsave %{_sysconfdir}/vomses
fi

%files
%defattr(-,root,root,-)
%{_libdir}/libvomsapi.so
%{_includedir}/voms
%{_libdir}/pkgconfig/voms-2.0.pc
%{_datadir}/aclocal/voms.m4
%{_mandir}/man3/*

%changelog
* Tue Apr 10 2011 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.8-1
- EMI 2 release.

* Thu Dec 15 2011 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.7-1
- Restructured EMI build to leverage EPEL spec files by Mattias Ellert
- Removed voms-java-apis from the main c-based source tree  
