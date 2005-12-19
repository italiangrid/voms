
noinst_LTLIBRARIES = liboldgaa.la \
	$(WANTED_OLDGAA_LIBS) # may add the libraries defined in EXTRA_LTLIBRARIES

SOURCES = oldgaa_alloc.c oldgaa_api.c oldgaa_gl_internal_err.c oldgaa_gl_internal_err.h oldgaa_policy_evaluator.c oldgaa_policy_evaluator.h oldgaa_release.c oldgaa_utils.c oldgaa_utils.h globus_oldgaa.h globus_oldgaa_utils.c globus_oldgaa_utils.h rfc1779.c

liboldgaa_la_SOURCES = $(SOURCES)

liboldgaa_la_CFLAGS = \
	$(GLOBUS_CFLAGS)

liboldgaa_la_LIBADD = \
	$(GLOBUS_GSS_LIBS)

###

EXTRA_LTLIBRARIES = \
	liboldgaa_gcc32.la \
	liboldgaa_gcc32dbg.la \
	liboldgaa_gcc32pthr.la \
	liboldgaa_gcc32dbgpthr.la

liboldgaa_gcc32_la_SOURCES = \
	$(SOURCES)

liboldgaa_gcc32_la_CFLAGS = \
	$(GLOBUS_GCC32_CFLAGS)

liboldgaa_gcc32_la_LIBADD = \
	$(GLOBUS_GCC32_GSS_LIBS)

liboldgaa_gcc32dbg_la_SOURCES = \
	$(SOURCES)

liboldgaa_gcc32dbg_la_CFLAGS = \
	$(GLOBUS_GCC32DBG_CFLAGS)

liboldgaa_gcc32dbg_la_LIBADD = \
	$(GLOBUS_GCC32DBG_GSS_LIBS)

liboldgaa_gcc32pthr_la_SOURCES = \
	$(SOURCES)

liboldgaa_gcc32pthr_la_CFLAGS = \
	$(GLOBUS_GCC32PTHR_CFLAGS)

liboldgaa_gcc32pthr_la_LIBADD = \
	$(GLOBUS_GCC32PTHR_GSS_LIBS)

liboldgaa_gcc32dbgpthr_la_SOURCES = \
	$(SOURCES)

liboldgaa_gcc32dbgpthr_la_CFLAGS = \
	$(GLOBUS_GCC32DBGPTHR_CFLAGS)

liboldgaa_gcc32dbgpthr_la_LIBADD = \
	$(GLOBUS_GCC32DBGPTHRGSS_LIBS)

CLEANFILES = \
	liboldgaa_gcc32.la \
	liboldgaa_gcc32dbg.la \
	liboldgaa_gcc32pthr.la \
	liboldgaa_gcc32dbgpthr.la