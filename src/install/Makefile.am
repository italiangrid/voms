sysconfigdir = @sysconfdir@/sysconfig

vomsesdir = @datadir@/voms

if BUILD_CONFIG
vomses_DATA = \
	vomses.template \
	voms.data
endif

libexecdir = @datadir@/voms

if BUILD_CONFIG
libexec_SCRIPTS = \
	voms_install_db \
	upgrade1to2 \
	voms-ping \
	mysql2oracle
endif

initdir = @sysconfdir@/rc.d/init.d

EXTRA_DIST = \
	vomses.template \
	voms.data \
	mysql2oracle \
	voms_install_db \
	upgrade1to2 \
	voms.start \
	voms-ping \
	voms.sh.in \
	sysconfig-voms

MAINTAINERCLEANFILES = Makefile.in

if BUILD_SERVER
install-exec-hook: voms.start
	$(mkinstalldirs) $(DESTDIR)$(initdir)
	$(INSTALL) $(top_builddir)/src/install/voms.start $(DESTDIR)$(initdir)/voms

install-data-hook: sysconfig-voms
	$(mkinstalldirs) $(DESTDIR)$(sysconfigdir)
	$(INSTALL) -m 644 $(top_builddir)/src/install/sysconfig-voms $(DESTDIR)$(sysconfigdir)/voms
endif
