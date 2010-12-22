includedir = @includedir@/voms

if BUILD_INTERFACES
include_HEADERS = \
	vomsproxy.h
endif

noinst_LTLIBRARIES = libssl_utils_nog.la

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

libssl_utils_nog_la_SOURCES= $(SOURCES)

libssl_utils_la_CFLAGS = \
	-I $(top_srcdir)/src/include

libssl_utils_nog_la_CFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-I $(top_srcdir)/src/include

###
