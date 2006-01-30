
noinst_LTLIBRARIES = \
	libattcert.la \
	libccattcert.la \
	$(WANTED_ATTCERT_LIBS) # may add the libraries defined in EXTRA_LTLIBRARIES

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

libattcert_la_LIBADD = \
	$(GLOBUS_GSS_LIBS)

libccattcert_la_SOURCES = \
	create.cc \
	ccinit.cc

libccattcert_la_LIBADD  = \
	libattcert.la \
	$(GLOBUS_GSS_LIBS)

AM_CPPFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils

###

EXTRA_LTLIBRARIES = \
	libattcert_gcc32.la \
	libattcert_gcc32dbg.la \
	libattcert_gcc32pthr.la \
	libattcert_gcc32dbgpthr.la \
	libattcert_gcc64.la \
	libattcert_gcc64dbg.la \
	libattcert_gcc64pthr.la \
	libattcert_gcc64dbgpthr.la \
	libccattcert_gcc32.la \
	libccattcert_gcc32dbg.la \
	libccattcert_gcc32pthr.la \
	libccattcert_gcc32dbgpthr.la \
	libccattcert_gcc64.la \
	libccattcert_gcc64dbg.la \
	libccattcert_gcc64pthr.la \
	libccattcert_gcc64dbgpthr.la

libattcert_gcc32_la_SOURCES = \
	validate.c \
	write.c \
	extensions.c \
	mystack.c \
	error.c \
	newformat.c \
	init.c

libattcert_gcc32_la_CFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils \
	$(GLOBUS_GCC32_CFLAGS)

libattcert_gcc32_la_LIBADD = \
	$(GLOBUS_GCC32_GSS_LIBS)

libccattcert_gcc32_la_SOURCES = \
	create.cc \
	ccinit.cc

libccattcert_gcc32_la_LIBADD  = \
	libattcert_gcc32.la \
	$(GLOBUS_GCC32_GSS_LIBS)

libattcert_gcc32dbg_la_SOURCES = \
	validate.c \
	write.c \
	extensions.c \
	mystack.c \
	error.c \
	newformat.c \
	init.c

libattcert_gcc32dbg_la_CFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils \
	$(GLOBUS_GCC32DBG_CFLAGS)

libattcert_gcc32dbg_la_LIBADD = \
	$(GLOBUS_GCC32DBG_GSS_LIBS)

libccattcert_gcc32dbg_la_SOURCES = \
	create.cc \
	ccinit.cc

libccattcert_gcc32dbg_la_LIBADD  = \
	libattcert_gcc32dbg.la \
	$(GLOBUS_GCC32DBG_GSS_LIBS)

libattcert_gcc32pthr_la_SOURCES = \
	validate.c \
	write.c \
	extensions.c \
	mystack.c \
	error.c \
	newformat.c \
	init.c

libattcert_gcc32pthr_la_CFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils \
	$(GLOBUS_GCC32PTHR_CFLAGS)

libattcert_gcc32pthr_la_LIBADD = \
	$(GLOBUS_GCC32PTHR_GSS_LIBS)

libccattcert_gcc32pthr_la_SOURCES = \
	create.cc \
	ccinit.cc

libccattcert_gcc32pthr_la_LIBADD  = \
	libattcert_gcc32pthr.la \
	$(GLOBUS_GCC32PTHR_GSS_LIBS)

libattcert_gcc32dbgpthr_la_SOURCES = \
	validate.c \
	write.c \
	extensions.c \
	mystack.c \
	error.c \
	newformat.c \
	init.c

libattcert_gcc32dbgpthr_la_CFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils \
	$(GLOBUS_GCC32DBGPTHR_CFLAGS)

libattcert_gcc32dbgpthr_la_LIBADD = \
	$(GLOBUS_GCC32DBGPTHR_GSS_LIBS)

libccattcert_gcc32dbgpthr_la_SOURCES = \
	create.cc \
	ccinit.cc

libccattcert_gcc32dbgpthr_la_LIBADD  = \
	libattcert_gcc32dbgpthr.la \
	$(GLOBUS_GCC32DBGPTHR_GSS_LIBS)

libattcert_gcc64_la_SOURCES = \
	validate.c \
	write.c \
	extensions.c \
	mystack.c \
	error.c \
	newformat.c \
	init.c

libattcert_gcc64_la_CFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils \
	$(GLOBUS_GCC64_CFLAGS)

libattcert_gcc64_la_LIBADD = \
	$(GLOBUS_GCC64_GSS_LIBS)

libccattcert_gcc64_la_SOURCES = \
	create.cc \
	ccinit.cc

libccattcert_gcc64_la_LIBADD  = \
	libattcert_gcc64.la \
	$(GLOBUS_GCC64_GSS_LIBS)

libattcert_gcc64dbg_la_SOURCES = \
	validate.c \
	write.c \
	extensions.c \
	mystack.c \
	error.c \
	newformat.c \
	init.c

libattcert_gcc64dbg_la_CFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils \
	$(GLOBUS_GCC64DBG_CFLAGS)

libattcert_gcc64dbg_la_LIBADD = \
	$(GLOBUS_GCC64DBG_GSS_LIBS)

libccattcert_gcc64dbg_la_SOURCES = \
	create.cc \
	ccinit.cc

libccattcert_gcc64dbg_la_LIBADD  = \
	libattcert_gcc64dbg.la \
	$(GLOBUS_GCC64DBG_GSS_LIBS)

libattcert_gcc64pthr_la_SOURCES = \
	validate.c \
	write.c \
	extensions.c \
	mystack.c \
	error.c \
	newformat.c \
	init.c

libattcert_gcc64pthr_la_CFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils \
	$(GLOBUS_GCC64PTHR_CFLAGS)

libattcert_gcc64pthr_la_LIBADD = \
	$(GLOBUS_GCC64PTHR_GSS_LIBS)

libccattcert_gcc64pthr_la_SOURCES = \
	create.cc \
	ccinit.cc

libccattcert_gcc64pthr_la_LIBADD  = \
	libattcert_gcc64pthr.la \
	$(GLOBUS_GCC64PTHR_GSS_LIBS)

libattcert_gcc64dbgpthr_la_SOURCES = \
	validate.c \
	write.c \
	extensions.c \
	mystack.c \
	error.c \
	newformat.c \
	init.c

libattcert_gcc64dbgpthr_la_CFLAGS= \
	-I $(top_srcdir)/src/include \
	-I $(top_builddir)/src/sslutils \
	$(GLOBUS_GCC64DBGPTHR_CFLAGS)

libattcert_gcc64dbgpthr_la_LIBADD = \
	$(GLOBUS_GCC64DBGPTHR_GSS_LIBS)

libccattcert_gcc64dbgpthr_la_SOURCES = \
	create.cc \
	ccinit.cc

libccattcert_gcc64dbgpthr_la_LIBADD  = \
	libattcert_gcc64dbgpthr.la \
	$(GLOBUS_GCC64DBGPTHR_GSS_LIBS)

EXTRA_DIST = \
	acerrors.h \
	write.h \
	init.h \
	extensions.h \
	test.c
