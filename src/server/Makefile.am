if BUILD_SERVER
sbin_PROGRAMS = voms

voms_SOURCES = \
	main.cc \
	vomsd.cc \
	vomsd-rest.cc \
	VOMSServer.h \
	attribute.h \
	uuid.c \
	uuid.h \
	attribute.cc \
	soapC.c \
	stdsoap2.c

#	$(top_builddir)/src/sslutils/libssl_utils_nog.la 

voms_LDADD = \
	$(top_builddir)/src/socklib/libsock_nog.la \
	$(top_builddir)/src/common/libutilities.la \
	$(top_builddir)/src/ac/libattributes_nog.la \
	$(top_builddir)/src/common/libutilc_nog.la \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/log/liblog.la \
	$(top_builddir)/src/api/ccapi/libvomsapi.la \
	$(EXPAT_LIBS)

voms_LDFLAGS =

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/api/ccapi \
  -DWITH_SOAPDEFS_H \
	$(NO_GLOBUS_FLAGS)

endif