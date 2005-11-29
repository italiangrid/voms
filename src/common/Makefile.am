
noinst_LTLIBRARIES = \
	libutilities.la \
	libutilc.la

libutilities_la_SOURCES = \
	data.cc \
	options.cc \
	pass.cc \
	sign.cc \
	xmlcc.cc

libutilc_la_SOURCES = \
	list.c \
	xml.c \
	error.c \
	credentials.c

AM_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(GLOBUS_CFLAGS)
