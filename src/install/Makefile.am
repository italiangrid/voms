
defaultsysconfdir = @sysconfdir@

if BUILD_CONFIG
defaultsysconf_DATA = \
	vomses.template
endif

sysconfdir = @sysconfdir@/voms

if BUILD_CONFIG
sysconf_DATA = \
	voms.data
endif

libexecdir = @libexecdir@/voms

if BUILD_CONFIG
libexec_SCRIPTS = \
	voms_install_db \
	upgrade1to2 \
	voms-ping \
	mysql2oracle
endif

initdir = @sysconfdir@/init.d

EXTRA_DIST = \
	vomses.template \
	voms.data \
	mysql2oracle \
	voms_install_db \
	upgrade1to2 \
	voms.start \
	voms-ping \
	voms.sh.in

MAINTAINERCLEANFILES = Makefile.in

if BUILD_SERVER
install-exec-hook: voms.start
	$(mkinstalldirs) $(DESTDIR)$(initdir)
	$(INSTALL) $(top_builddir)/src/install/voms.start $(DESTDIR)$(initdir)/voms
endif