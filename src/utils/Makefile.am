
bin_PROGRAMS = \
	voms-proxy-info \
	voms-proxy-destroy \
	voms-proxy-fake

voms_proxy_info_SOURCES = \
	voms_proxy_info.cc

voms_proxy_info_LDADD = \
	$(top_builddir)/src/api/ccapi/libvomsapi.la  \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/log/liblog.la \
	$(top_builddir)/src/sslutils/libssl_utils_nog.la \
	$(EXPAT_LIBS)

voms_proxy_destroy_SOURCES = \
	voms_proxy_destroy.cc

voms_proxy_destroy_LDADD = \
	$(top_builddir)/src/api/ccapi/libvomsapi.la  \
	$(top_builddir)/src/sslutils/libssl_utils_nog.la \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/log/liblog.la \
	$(EXPAT_LIBS)

voms_proxy_fake_SOURCES = \
	vomsfake.h \
	vomsfake.cc

voms_proxy_fake_LDADD = \
	$(top_builddir)/src/common/libutilities.la \
	$(top_builddir)/src/ac/libattributes_nog.la \
	$(top_builddir)/src/common/libutilc.la \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/sslutils/libssl_utils_nog.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/api/ccapi \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/sslutils \
	$(GLOBUS_CFLAGS)

install-exec-hook:
	-ln -s voms-proxy-info $(DESTDIR)$(bindir)/edg-voms-proxy-info
	-ln -s voms-proxy-destroy $(DESTDIR)$(bindir)/edg-voms-proxy-destroy
	-ln -s voms-proxy-fake $(DESTDIR)$(bindir)/edg-voms-proxy-fake
if ENABLE_GLITE
	-ln -s voms-proxy-info $(DESTDIR)$(bindir)/glite-voms-proxy-info
	-ln -s voms-proxy-destroy $(DESTDIR)$(bindir)/glite-voms-proxy-destroy
	-ln -s voms-proxy-fake $(DESTDIR)$(bindir)/glite-voms-proxy-fake
endif
