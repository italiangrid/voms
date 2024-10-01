
AM_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(EXPAT_CFLAGS) \
	$(OPENSSL_CFLAGS)

AM_LDFLAGS = \
	$(EXPAT_LIBS) \
	$(OPENSSL_LIBS)

noinst_LTLIBRARIES = \
	libutilities_nog.la \
	libutilc_nog.la

libutilities_nog_la_SOURCES = \
	data.cc \
	options.cc \
	pass.cc \
	fqan.cc \
	xmlcc.cc

libutilities_nog_la_CFLAGS = \
	-DNOGLOBUS \
	$(NO_GLOBUS_FLAGS)

libutilc_nog_la_CFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-DNOGLOBUS

libutilc_nog_la_SOURCES = \
	list.c \
	failure.c \
	doio.c \
	normalize.c \
	credentials.c
