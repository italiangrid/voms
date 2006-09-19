
noinst_LTLIBRARIES = \
	libutilities.la \
	libutilities_nog.la \
	libutilc_nog.la \
	libutilc.la

libutilities_la_SOURCES = \
	data.cc \
	options.cc \
	pass.cc \
	xmlcc.cc

libutilities_nog_la_SOURCES = \
	data.cc \
	options.cc \
	pass.cc \
	xmlcc.cc

libutilities_nog_la_CFLAGS = \
	-DNOGLOBUS \
	$(NO_GLOBUS_FLAGS) \
	-I $(top_srcdir)/src/include

libutilc_la_SOURCES = \
	list.c \
	xml.c \
	error.c \
	credentials.c

AM_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(GLOBUS_CFLAGS)

libutilc_nog_la_CPPFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-DNOGLOBUS \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(GLOBUS_CFLAGS)

libutilc_nog_la_SOURCES = \
	list.c \
	xml.c \
	error.c \
	credentials.c
