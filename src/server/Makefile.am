if BUILD_SERVER
sbin_PROGRAMS = voms

voms_SOURCES = \
	main.cc \
	vomsd.cc \
	VOMSServer.h \
	attribute.h \
	uuid.c \
	uuid.h \
	attribute.cc \
	soapC.c \
	soapServer.c \
	stdsoap2.c

voms_LDADD = \
	$(top_builddir)/src/socklib/$(USE_SOCK_LIB_SERVER) \
	$(top_builddir)/src/common/libutilities_nog.la \
	$(top_builddir)/src/sslutils/$(USE_SSL_UTILS_LIB) \
	$(top_builddir)/src/ac/$(USE_CCATTCERT_LIB) \
	$(top_builddir)/src/common/libutilc_nog.la \
	$(top_builddir)/src/ac/$(USE_ATTCERT_LIB) \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/log/liblog.la \
	$(top_builddir)/src/api/ccapi/$(USE_CCAPI_LIB) \
	$(EXPAT_LIBS)

voms_LDFLAGS =

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/api/ccapi \
  -DWITH_SOAPDEFS_H \
	$(GLOBUS_CFLAGS)

install-exec-hook:
	-ln -s voms $(DESTDIR)$(sbindir)/edg-voms
if ENABLE_GLITE
	-ln -s voms $(DESTDIR)$(sbindir)/glite-voms
endif
endif