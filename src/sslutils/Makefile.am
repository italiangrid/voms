includedir = @includedir@/glite/security/voms

if BUILD_INTERFACES
include_HEADERS = \
	vomsproxy.h
endif

noinst_LTLIBRARIES = \
	$(WANTED_SSL_UTILS_LIBS) # may add the libraries defined in EXTRA_LTLIBRARIES

SOURCES= scutils.c scutils.h sslutils.c sslutils.h proxycertinfo.c \
	signing_policy.c lex.signing.c namespaces.c lex.namespaces.c \
	evaluate.c proxy.c vomsproxy.h

evaluate.$(OBJEXT): signing_policy.h namespaces.h

signing_policy.$(OBJEXT): signing_policy.h

signing_policy.h signing_policy.c: signing_policy.y
	bison -t -d -o signing_policy.c signing_policy.y

lex.signing.c: signing_policy.l signing_policy.h signing_policy.c
	flex -b -f -d signing_policy.l

namespaces.$(OBJEXT): namespaces.h

namespaces.h namespaces.c: namespaces.y
	bison -t -d -o namespaces.c namespaces.y

lex.namespaces.c: namespaces.l namespaces.h namespaces.c
	flex -b -f -d namespaces.l

libssl_utils_la_SOURCES= $(SOURCES)
libssl_utils_nog_la_SOURCES= $(SOURCES)

libssl_utils_la_CFLAGS = \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_CFLAGS)

libssl_utils_la_LIBADD = \
	$(GLOBUS_GSS_API_LIBS)

libssl_utils_nog_la_CFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_CFLAGS)

###

EXTRA_LTLIBRARIES = \
	libssl_utils_gcc32.la \
	libssl_utils_gcc32dbg.la \
	libssl_utils_gcc32pthr.la \
	libssl_utils_gcc32dbgpthr.la \
	libssl_utils_gcc64.la \
	libssl_utils_gcc64dbg.la \
	libssl_utils_gcc64pthr.la \
	libssl_utils_gcc64dbgpthr.la \
	libssl_utils.la \
	libssl_utils_nog.la

libssl_utils_gcc32_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc32_la_CFLAGS = \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC32_CFLAGS)

libssl_utils_gcc32_la_LIBADD = \
	$(GLOBUS_GCC32_GSS_API_LIBS)

libssl_utils_gcc32dbg_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc32dbg_la_CFLAGS = \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC32DBG_CFLAGS)

libssl_utils_gcc32dbg_la_LIBADD = \
	$(GLOBUS_GCC32DBG_GSS_API_LIBS)

libssl_utils_gcc32pthr_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc32pthr_la_CFLAGS = \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC32PTHR_CFLAGS)

libssl_utils_gcc32pthr_la_LIBADD = \
	$(GLOBUS_GCC32PTHR_GSS_API_LIBS)

libssl_utils_gcc32dbgpthr_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc32dbgpthr_la_CFLAGS = \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC32DBGPTHR_CFLAGS)

libssl_utils_gcc32dbgpthr_la_LIBADD = \
	$(GLOBUS_GCC32DBGPTHR_GSS_API_LIBS)

libssl_utils_gcc64_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc64_la_CFLAGS = \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC64_CFLAGS)

libssl_utils_gcc64_la_LIBADD = \
	$(GLOBUS_GCC64_GSS_API_LIBS)

libssl_utils_gcc64dbg_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc64dbg_la_CFLAGS = \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC64DBG_CFLAGS)

libssl_utils_gcc64dbg_la_LIBADD = \
	$(GLOBUS_GCC64DBG_GSS_API_LIBS)

libssl_utils_gcc64pthr_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc64pthr_la_CFLAGS = \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC64PTHR_CFLAGS)

libssl_utils_gcc64pthr_la_LIBADD = \
	$(GLOBUS_GCC64PTHR_GSS_API_LIBS)

libssl_utils_gcc64dbgpthr_la_SOURCES= \
	$(SOURCES)

libssl_utils_gcc64dbgpthr_la_CFLAGS = \
	-I $(top_srcdir)/src/include \
	$(GLOBUS_GCC64DBGPTHR_CFLAGS)

libssl_utils_gcc64dbgpthr_la_LIBADD = \
	$(GLOBUS_GCC64DBGPTHR_GSS_API_LIBS)

CLEANFILES = \
	libssl_utils_gcc64.la \
	libssl_utils_gcc64dbg.la \
	libssl_utils_gcc64pthr.la \
	libssl_utils_gcc64dbgpthr.la \
	libssl_utils_gcc32.la \
	libssl_utils_gcc32dbg.la \
	libssl_utils_gcc32pthr.la \
	libssl_utils_gcc32dbgpthr.la
