if BUILD_SERVER
sbin_PROGRAMS = voms

voms_SOURCES = \
	main.cc \
	vomsd.cc \
	vomsd-rest.cc \
	VOMSServer.h \
	attribute.h \
	uuid.c \
	uuid.h \
	attribute.cc

nodist_voms_SOURCES = \
	soapC.cpp \
	soapH.h \
	soapStub.h

vomsd.$(OBJEXT) vomsd-rest.$(OBJEXT): soapH.h
voms-vomsd.$(OBJEXT) voms-vomsd-rest.$(OBJEXT): soapH.h
soapH.h soapStub.h: soapC.cpp

soapC.cpp: VOMSAC.h
	$(SOAPCPP2) VOMSAC.h

VOMSAC.h: $(top_srcdir)/src/server/VOMSAC.wsdl
	$(WSDL2H) $(WSDL2H_FLAGS) -s -o $@ $(top_srcdir)/src/server/VOMSAC.wsdl

EXTRA_DIST= VOMSAC.wsdl
CLEANFILES= soap* VOMSAC.h vomsSOAP*

voms_LDADD = \
	$(top_builddir)/src/socklib/libsock_nog.la \
	$(top_builddir)/src/common/libutilities_nog.la \
	$(top_builddir)/src/ac/libattributes_nog.la \
	$(top_builddir)/src/common/libutilc_nog.la \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/log/liblog.la \
	$(top_builddir)/src/api/ccapi/libvomsapi.la \
	$(GSOAP_SSL_PP_LIBS) \
	$(OPENSSL_LIBS) \
	$(EXPAT_LIBS) \
	-ldl 

voms_CFLAGS = $(GSOAP_SSL_PP_CFLAGS) -DHAVE_OPENSSL_SSL_H

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/api/ccapi \
	$(NO_GLOBUS_FLAGS)

endif
