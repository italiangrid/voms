includedir = @includedir@/voms

if BUILD_INTERFACES
include_HEADERS = \
	vomsssl.h
endif

noinst_LTLIBRARIES = libsock_nog.la

SOURCES = Client.cpp ipv6sock.cc io.cc

libsock_nog_la_SOURCES = Client.cpp Server.cpp ipv6sock.cc io.cc

libsock_nog_la_CXXFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils

libsock_nog_la_LIBADD = \
	-lcrypto -lssl
#	$(top_builddir)/src/sslutils/libssl_utils_nog.la \
#	$(top_builddir)/src/common/libutilc_nog.la

EXTRA_DIST = vomsssl.h ipv6sock.h io.h

###

CLEANFILES = \
	libsock_nog.la \
	libsock.la

###
