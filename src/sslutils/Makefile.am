
SUBDIRS = oldgaa

noinst_LTLIBRARIES = \
	libssl_utils.la \
	$(WANTED_SSL_UTILS_LIBS) # may add the libraries defined in EXTRA_LTLIBRARIES

SOURCES= scutils.c scutils.h sslutils.c sslutils.h proxycertinfo.c

libssl_utils_la_SOURCES= $(SOURCES)

libssl_utils_la_CFLAGS = \
	-I $(top_srcdir)/src/sslutils/oldgaa \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_CFLAGS)

libssl_utils_la_LIBADD = \
	./oldgaa/liboldgaa.la \
	$(GLOBUS_GSS_LIBS)

###

EXTRA_LTLIBRARIES = \
	libssl_utils_gcc32.la \
	libssl_utils_gcc32dbg.la \
	libssl_utils_gcc32pthr.la \
	libssl_utils_gcc32dbgpthr.la

libssl_utils_gcc32_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc32_la_CFLAGS = \
	-I $(top_srcdir)/src/sslutils/oldgaa \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC32_CFLAGS)

libssl_utils_gcc32_la_LIBADD = \
	./oldgaa/liboldgaa_gcc32.la \
	$(GLOBUS_GCC32_GSS_LIBS)

libssl_utils_gcc32dbg_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc32dbg_la_CFLAGS = \
	-I $(top_srcdir)/src/sslutils/oldgaa \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC32DBG_CFLAGS)

libssl_utils_gcc32dbg_la_LIBADD = \
	./oldgaa/liboldgaa_gcc32dbg.la \
	$(GLOBUS_GCC32DBG_GSS_LIBS)

libssl_utils_gcc32pthr_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc32pthr_la_CFLAGS = \
	-I $(top_srcdir)/src/sslutils/oldgaa \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC32PTHR_CFLAGS)

libssl_utils_gcc32pthr_la_LIBADD = \
	./oldgaa/liboldgaa_gcc32pthr.la \
	$(GLOBUS_GCC32PTHR_GSS_LIBS)

libssl_utils_gcc32dbgpthr_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc32dbgpthr_la_CFLAGS = \
	-I $(top_srcdir)/src/sslutils/oldgaa \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC32DBGPTHR_CFLAGS)

libssl_utils_gcc32dbgpthr_la_LIBADD = \
	./oldgaa/liboldgaa_gcc32dbgpthr.la \
	$(GLOBUS_GCC32DBGPTHR_GSS_LIBS)

CLEANFILES = \
	libssl_utils_gcc32.la \
	libssl_utils_gcc32dbg.la \
	libssl_utils_gcc32pthr.la \
	libssl_utils_gcc32dbgpthr.la
