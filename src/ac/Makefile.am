
noinst_LTLIBRARIES = \
	libattcert.la \
	libccattcert.la

libattcert_la_SOURCES = \
	validate.c \
	write.c \
	extensions.c \
	mystack.c \
	error.c \
	newformat.c \
	init.c

libattcert_la_CFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils \
	$(GLOBUS_CFLAGS)

libccattcert_la_SOURCES = \
	create.cc \
	ccinit.cc

AM_CPPFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils

libccattcert_la_LIBADD  = \
	libattcert.la

EXTRA_DIST = \
	acerrors.h \
	write.h \
	init.h \
	extensions.h \
	test.c
