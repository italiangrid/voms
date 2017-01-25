includedir = @includedir@/voms

if BUILD_INTERFACES
include_HEADERS = \
	vomsproxy.h
endif

noinst_LTLIBRARIES = libssl_utils_nog.la

SOURCES= scutils.c scutils.h sslutils.c proxycertinfo.c proxypolicy.c \
	signing_policy.c lex.signing.c namespaces.c lex.namespaces.c \
	evaluate.c proxy.c vomsproxy.h voms_cert_type.h  voms_cert_type.c \
	ssl_compat.c


EXTRA_DIST = 	namespaces.l namespaces.y namespaces.h \
		signing_policy.y signing_policy.l signing_policy.h \
		parsertypes.h

evaluate.$(OBJEXT): signing_policy.h namespaces.h parsertypes.h evaluate.c

signing_policy.$(OBJEXT): signing_policy.h

if REGENERATE_PARSERS

signing_policy.h signing_policy.c: signing_policy.y
	$(YACC) -t -d -o signing_policy.c signing_policy.y


lex.signing.c: signing_policy.l signing_policy.h signing_policy.c
	$(LEX) -b -f -d signing_policy.l
endif

namespaces.$(OBJEXT): namespaces.h

if REGENERATE_PARSERS

namespaces.h namespaces.c: namespaces.y
	$(YACC) -t -d -o namespaces.c namespaces.y

lex.namespaces.c: namespaces.l namespaces.h namespaces.c
	$(LEX) -b -f -d namespaces.l
endif

libssl_utils_nog_la_SOURCES= $(SOURCES)

libssl_utils_la_CFLAGS = \
	-I $(top_srcdir)/src/include

libssl_utils_nog_la_CFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-I $(top_srcdir)/src/include

###
