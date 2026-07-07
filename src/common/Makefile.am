
AM_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(EXPAT_CFLAGS) \
	$(OPENSSL_CFLAGS)

AM_LDFLAGS = \
	$(EXPAT_LIBS) \
	$(OPENSSL_LIBS)

noinst_LTLIBRARIES = \
	libutilities.la \
	libutilc.la

libutilities_la_SOURCES = \
	data.cc \
	options.cc \
	pass.cc \
	fqan.cc \
	xmlcc.cc

libutilc_la_SOURCES = \
	list.c \
	failure.c \
	doio.c \
	normalize.c \
	credentials.c
