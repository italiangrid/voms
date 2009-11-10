
defaultsysconfdir = @sysconfdir@

defaultsysconf_DATA = \
	vomses.template

sysconfdir = @sysconfdir@/voms

sysconf_DATA = \
	voms.data

libexecdir = @libexecdir@/voms

libexec_SCRIPTS = \
	voms_install_db \
	upgrade1to2 \
	voms-ping \
	mysql2oracle

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

install-exec-hook: voms.start
	$(mkinstalldirs) $(DESTDIR)$(initdir)
	$(INSTALL) $(top_builddir)/src/install/voms.start $(DESTDIR)$(initdir)/voms
