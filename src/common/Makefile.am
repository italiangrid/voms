
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
	$(NO_GLOBUS_FLAGS) \
	-I $(top_srcdir)/src/include

AM_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(EXPAT_CFLAGS)

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
