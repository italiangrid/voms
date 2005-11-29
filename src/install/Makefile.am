
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

init_SCRIPTS = \
	voms.start

EXTRA_DIST = \
	vomses.template \
	voms.data \
	mysql2oracle \
	voms_install_db \
	upgrade1to2 \
	voms.start

MAINTAINERCLEANFILES = Makefile.in
