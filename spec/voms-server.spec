Name: voms-server
Version: 2.0.8
Release: 1%{?dist}

Summary:	Virtual Organization Membership Service Server
Group:		Applications/Internet

Requires:	voms%{?_isa} = %{version}-%{release}
Requires(pre):		shadow-utils
Requires(post):		chkconfig
Requires(preun):	chkconfig
Requires(preun):	initscripts
Requires(postun):	initscripts

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

This package provides the VOMS service.

%prep
%setup -q -n voms-%{version}
./autogen.sh

%build

%configure --disable-static --enable-docs --disable-parser-gen \
        --without-all --with-server --with-config

make %{?_smp_mflags}

%install

rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm $RPM_BUILD_ROOT%{_mandir}/man3/*.3*
rm $RPM_BUILD_ROOT%{_datadir}/voms/vomses.template

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/grid-security/vomsdir
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/grid-security/voms
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/log/voms
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/voms

%clean
rm -rf $RPM_BUILD_ROOT

%pre 
getent group voms >/dev/null || groupadd -r voms
getent passwd voms >/dev/null || useradd -r -g voms \
    -d %{_sysconfdir}/voms -s /sbin/nologin -c "VOMS Server Account" voms
exit 0

%post 
if [ $1 = 1 ]; then
    /sbin/chkconfig --add voms
fi

%preun 
if [ $1 = 0 ]; then
    /sbin/service voms stop >/dev/null 2>&1 || :
    /sbin/chkconfig --del voms
fi

%postun 
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
%{_mandir}/man8/voms.8*

%changelog
* Tue Apr 10 2011 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.8-1
- EMI 2 release.

* Thu Dec 15 2011 Andrea Ceccanti <andrea.ceccanti at cnaf.infn.it> - 2.0.7-1
- Restructured EMI build to leverage EPEL spec files by Mattias Ellert
- Removed voms-java-apis from the main c-based source tree  
