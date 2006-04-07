
bin_PROGRAMS = voms-proxy-init

voms_proxy_init_SOURCES = \
	main.cc \
	vomsclient.cc \
	vomsclient.h \
	contact.hpp \
	fqan.h \
	fqan.cc

voms_proxy_init_LDADD = \
	$(top_builddir)/src/common/libutilities.la \
	$(top_builddir)/src/ac/libattcert.la \
	$(top_builddir)/src/ac/libccattcert.la \
	$(top_builddir)/src/common/libutilc.la \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/log/liblog.la \
	$(top_builddir)/src/api/ccapi/libvomsapi.la \
	$(top_builddir)/src/sslutils/libssl_utils.la \
	$(EXPAT_LIBS)

AM_CPPFLAGS = -I$(top_srcdir)/src/api/ccapi \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/sslutils \
	$(GLOBUS_CFLAGS) \
	$(EXPAT_CFLAGS)

install-exec-hook:
	-ln -s voms-proxy-init $(DESTDIR)$(bindir)/edg-voms-proxy-init
	-ln -s voms-proxy-init $(DESTDIR)$(bindir)/voms-proxy-list
	-ln -s voms-proxy-init $(DESTDIR)$(bindir)/edg-voms-proxy-list
if ENABLE_GLITE
	-ln -s voms-proxy-init $(DESTDIR)$(bindir)/glite-voms-proxy-init
	-ln -s voms-proxy-init $(DESTDIR)$(bindir)/glite-voms-proxy-list
endif
