includedir = @includedir@/voms

if BUILD_INTERFACES
include_HEADERS = \
	vomsssl.h
endif

noinst_LTLIBRARIES = libsock.la

SOURCES = Client.cpp ipv6sock.cc io.cc

libsock_la_SOURCES = Client.cpp Server.cpp ipv6sock.cc io.cc

libsock_la_CXXFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(OPENSSL_CFLAGS)

libsock_la_LIBADD = \
	-lcrypto -lssl

EXTRA_DIST = vomsssl.h ipv6sock.h io.h

CLEANFILES = \
	libsock.la \
	libsock.la
