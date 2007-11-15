
sbin_PROGRAMS = voms

voms_SOURCES = \
	main.cc \
	vomsd.cc \
	VOMSServer.h \
	attribute.h \
	uuid.c \
	uuid.h \
	attribute.cc

voms_LDADD = \
	$(top_builddir)/src/socklib/$(USE_SOCK_LIB) \
	$(top_builddir)/src/common/libutilities.la \
	$(top_builddir)/src/sslutils/$(USE_SSL_UTILS_LIB) \
	$(top_builddir)/src/ac/$(USE_CCATTCERT_LIB) \
	$(top_builddir)/src/common/libutilc.la \
	$(top_builddir)/src/ac/$(USE_ATTCERT_LIB) \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/log/liblog.la \
	$(top_builddir)/src/api/ccapi/$(USE_CCAPI_LIB) \
	$(EXPAT_LIBS)

voms_LDFLAGS =

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/api/ccapi \
	$(GLOBUS_CFLAGS)

install-exec-hook:
	-ln -s voms $(DESTDIR)$(sbindir)/edg-voms
if ENABLE_GLITE
	-ln -s voms $(DESTDIR)$(sbindir)/glite-voms
endif
