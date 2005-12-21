
defaultsysconfdir = $(prefix)/etc

defaultsysconf_DATA = \
	vomses.template

sysconfdir = $(prefix)/etc/voms

sysconf_DATA = \
	voms.data

libexecdir = $(prefix)/libexec/voms

libexec_SCRIPTS = \
	voms_install_db \
	upgrade1to2 \
	mysql2oracle

initdir = $(prefix)/etc/init.d

EXTRA_DIST = \
	vomses.template \
	voms.data \
	mysql2oracle \
	voms_install_db \
	upgrade1to2 \
	voms.start \
	voms.sh.in

MAINTAINERCLEANFILES = Makefile.in

install-exec-hook: voms.start
	$(mkinstalldirs) $(DESTDIR)$(initdir)
	$(INSTALL) $(top_builddir)/src/install/voms.start $(DESTDIR)$(initdir)/voms
