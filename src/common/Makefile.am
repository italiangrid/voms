
noinst_LTLIBRARIES = \
	$(WANTED_UTIL_LIBS)

EXTRA_LTLIBRARIES = \
	libutilities.la \
	libutilities_nog.la \
	libutilc_nog.la \
	libutilc.la

libutilities_la_SOURCES = \
	data.cc \
	options.cc \
	pass.cc \
	fqan.cc \
	xmlcc.cc

libutilities_nog_la_SOURCES = \
	data.cc \
	options.cc \
	pass.cc \
	fqan.cc \
	xmlcc.cc

libutilities_nog_la_CFLAGS = \
	-DNOGLOBUS \
	$(NO_GLOBUS_FLAGS) \
	-I $(top_srcdir)/src/include

libutilc_la_SOURCES = \
	list.c \
	failure.c \
	doio.c \
	normalize.c \
	credentials.c

AM_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(EXPAT_CFLAGS) \
	$(GLOBUS_CFLAGS)

AM_LDFLAGS = \
	$(EXPAT_LIBS)

libutilc_nog_la_CPPFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-DNOGLOBUS \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(EXPAT_CFLAGS) 

libutilc_nog_la_SOURCES = \
	list.c \
	failure.c \
	doio.c \
	normalize.c \
	credentials.c
