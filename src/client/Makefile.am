if BUILD_CLIENTS
bin_PROGRAMS = voms-proxy-init

voms_proxy_init_SOURCES = \
	main.cc \
	vomsclient.cc \
	vomsclient.h \
	contact.hpp

voms_proxy_init_LDADD = \
  $(top_builddir)/src/api/ccapi/libvomsapi.la \
  $(top_builddir)/src/sslutils/libssl_utils_nog.la \
	$(OPENSSL_LIBS) \
  $(top_builddir)/src/common/libutilc_nog.la \
	$(EXPAT_LIBS)

AM_CPPFLAGS = -I$(top_srcdir)/src/api/ccapi \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/sslutils \
	$(NO_GLOBUS_FLAGS) \
	$(EXPAT_CFLAGS)

install-exec-hook:
	-ln -s voms-proxy-init $(DESTDIR)$(bindir)/voms-proxy-list
endif
