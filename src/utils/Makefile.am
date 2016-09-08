if BUILD_CLIENTS
bin_PROGRAMS = \
	voms-proxy-info \
	voms-proxy-destroy \
	voms-proxy-fake \
	voms-verify


voms_proxy_info_SOURCES = \
	voms_proxy_info.cc

voms_proxy_info_LDADD = \
	$(top_builddir)/src/api/ccapi/libvomsapi.la  \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/sslutils/libssl_utils_nog.la \
	$(OPENSSL_LIBS) \
	$(EXPAT_LIBS) 

voms_proxy_destroy_SOURCES = \
	voms_proxy_destroy.cc

voms_proxy_destroy_LDADD = \
	$(top_builddir)/src/api/ccapi/libvomsapi.la  \
	$(top_builddir)/src/sslutils/libssl_utils_nog.la \
	$(top_builddir)/src/replib/librep.la \
	$(OPENSSL_LIBS) \
	$(EXPAT_LIBS) 

voms_verify_SOURCES = \
	voms_verify.cc

voms_verify_LDADD = \
	$(top_builddir)/src/api/ccapi/libvomsapi.la  \
	$(top_builddir)/src/sslutils/libssl_utils_nog.la \
	$(top_builddir)/src/replib/librep.la \
	$(OPENSSL_LIBS) 

voms_proxy_fake_SOURCES = \
	vomsfake.h \
	vomsfake.cc \
	vomsparser.c \
	lex.yy.c 

EXTRA_DIST = vomsfake.y vomsparser.l vomsparser.h fakeparsertypes.h

vomsfake.$(OBJEXT): vomsparser.h

vomsparser.$(OBJEXT): vomsparser.h

if REGENERATE_PARSERS

vomsparser.h vomsparser.c: vomsfake.y
	$(YACC) -t -d -o vomsparser.c vomsfake.y

lex.yy.c: vomsparser.l vomsparser.h
	$(LEX) vomsparser.l
endif

voms_proxy_fake_LDADD = \
	$(top_builddir)/src/api/ccapi/libvomsapi.la  \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/sslutils/libssl_utils_nog.la \
	$(OPENSSL_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/api/ccapi \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/sslutils \
	$(NO_GLOBUS_FLAGS)

endif
