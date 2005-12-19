
noinst_LTLIBRARIES = \
	libsock.la \
	$(WANTED_SOCK_LIBS) # may add the libraries defined in EXTRA_LTLIBRARIES

SOURCES = Client.cpp Server.cpp tokens.c globuswrap.c

libsock_la_SOURCES = 	$(SOURCES)

libsock_la_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(GLOBUS_CFLAGS)

libsock_la_LIBADD = \
	$(top_builddir)/src/sslutils/libssl_utils.la \
	$(top_builddir)/src/common/libutilc.la \
	$(GLOBUS_GSS_LIBS)

EXTRA_DIST = globuswrap.h

###

EXTRA_LTLIBRARIES = \
	libsock_gcc32.la \
	libsock_gcc32dbg.la \
	libsock_gcc32pthr.la \
	libsock_gcc32dbgpthr.la

libsock_gcc32_la_SOURCES = \
	$(SOURCES)

libsock_gcc32_la_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(GLOBUS_GCC32_CFLAGS)

libsock_gcc32_la_LIBADD = \
	$(top_builddir)/src/sslutils/libssl_utils_gcc32.la \
	$(top_builddir)/src/common/libutilc.la \
	$(GLOBUS_GCC32_GSS_LIBS)

libsock_gcc32dbg_la_SOURCES = \
	$(SOURCES)

libsock_gcc32dbg_la_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(GLOBUS_GCC32DBG_CFLAGS)

libsock_gcc32dbg_la_LIBADD = \
	$(top_builddir)/src/sslutils/libssl_utils_gcc32dbg.la \
	$(top_builddir)/src/common/libutilc.la \
	$(GLOBUS_GCC32DBG_GSS_LIBS)

libsock_gcc32pthr_la_SOURCES = \
	$(SOURCES)

libsock_gcc32pthr_la_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(GLOBUS_GCC32PTHR_CFLAGS)

libsock_gcc32pthr_la_LIBADD = \
	$(top_builddir)/src/sslutils/libssl_utils_gcc32pthr.la \
	$(top_builddir)/src/common/libutilc.la \
	$(GLOBUS_GCC32PTHR_GSS_LIBS)

libsock_gcc32dbgpthr_la_SOURCES = \
	$(SOURCES)

libsock_gcc32dbgpthr_la_CPPFLAGS = \
	-I $(top_srcdir)/src/include \
	-I $(top_srcdir)/src/sslutils \
	$(GLOBUS_GCC32DBG_CFLAGS)

libsock_gcc32dbgpthr_la_LIBADD = \
	$(top_builddir)/src/sslutils/libssl_utils_gcc32dbgpthr.la \
	$(top_builddir)/src/common/libutilc.la \
	$(GLOBUS_GCC32DBGPTHR_GSS_LIBS)

CLEANFILES = \
	libsock_gcc32.la \
	libsock_gcc32dbg.la \
	libsock_gcc32pthr.la \
	libsock_gcc32dbgpthr.la
