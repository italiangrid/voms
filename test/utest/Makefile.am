
noinst_PROGRAMS = \
	vomsdata_cu \
	capi_cu \
	vomsclient_cu

vomsdata_cu_SOURCES = \
	vomsdata_cu_suite.h \
	vomsdata_cu_suite.cpp \
	vomsdata_cu_main.cpp \
	socket_mock.cpp \
	$(top_srcdir)/src/api/ccapi/voms_api.cc \
	$(top_srcdir)/src/api/ccapi/api_util.cc \
	$(top_srcdir)/src/api/ccapi/ccval.cc \
	$(top_srcdir)/src/ac/newformat.c \
	$(top_srcdir)/src/ac/mystack.c \
	$(top_srcdir)/src/ac/ccinit.cc \
	$(top_srcdir)/src/ac/init.c \
	$(top_srcdir)/src/ac/create.cc \
	$(top_srcdir)/src/ac/write.c \
	$(top_srcdir)/src/ac/extensions.c \
	$(top_srcdir)/src/ac/validate.c \
	$(top_srcdir)/src/common/credentials.c \
	$(top_srcdir)/src/common/xmlcc.cc \
	$(top_srcdir)/src/common/data.cc \
	$(top_srcdir)/src/common/xml.c \
	$(top_srcdir)/src/common/list.c \
	$(top_srcdir)/src/common/error.c \
	$(top_srcdir)/src/sslutils/sslutils.c

vomsdata_cu_LDADD  = \
	$(GLOBUS_GSS_LIBS) \
	$(EXPAT_LIBS) \
	$(CPPUNIT_LIBS)

capi_cu_SOURCES = \
	capi_cu_main.cpp \
	capi_cu_suite.h \
	capi_cu_suite.cpp \
	socket_mock.cpp \
	$(top_srcdir)/src/api/ccapi/cinterface.cc\
	$(top_srcdir)/src/api/ccapi/voms_api.cc \
	$(top_srcdir)/src/api/ccapi/api_util.cc \
	$(top_srcdir)/src/api/ccapi/ccval.cc \
	$(top_srcdir)/src/ac/newformat.c \
	$(top_srcdir)/src/ac/mystack.c \
	$(top_srcdir)/src/ac/init.c \
	$(top_srcdir)/src/ac/ccinit.cc \
	$(top_srcdir)/src/ac/create.cc \
	$(top_srcdir)/src/ac/write.c \
	$(top_srcdir)/src/ac/extensions.c \
	$(top_srcdir)/src/ac/validate.c \
	$(top_srcdir)/src/common/credentials.c \
	$(top_srcdir)/src/common/xmlcc.cc \
	$(top_srcdir)/src/common/data.cc \
	$(top_srcdir)/src/common/xml.c \
	$(top_srcdir)/src/common/list.c \
	$(top_srcdir)/src/common/error.c \
	$(top_srcdir)/src/sslutils/sslutils.c

capi_cu_LDADD  = \
	$(GLOBUS_GSS_LIBS) \
	$(EXPAT_LIBS) \
	$(CPPUNIT_LIBS)

vomsclient_cu_SOURCES = \
	vomsclient_cu_main.cpp \
	vomsclient_cu_suite.h \
	vomsclient_cu_suite.cpp \
	socket_mock.cpp \
	$(top_srcdir)/src/client/vomsclient.cc \
	$(top_srcdir)/src/client/fqan.cc \
	$(top_srcdir)/src/sslutils/proxycertinfo.c \
	$(top_srcdir)/src/api/ccapi/voms_api.cc\
	$(top_srcdir)/src/api/ccapi/api_util.cc \
	$(top_srcdir)/src/api/ccapi/ccval.cc \
	$(top_srcdir)/src/ac/newformat.c \
	$(top_srcdir)/src/ac/mystack.c \
	$(top_srcdir)/src/ac/ccinit.cc \
	$(top_srcdir)/src/ac/init.c \
	$(top_srcdir)/src/ac/create.cc \
	$(top_srcdir)/src/ac/write.c \
	$(top_srcdir)/src/ac/extensions.c \
	$(top_srcdir)/src/ac/validate.c \
	$(top_srcdir)/src/common/credentials.c \
	$(top_srcdir)/src/common/xmlcc.cc \
	$(top_srcdir)/src/common/data.cc \
	$(top_srcdir)/src/common/options.cc \
	$(top_srcdir)/src/common/xml.c \
	$(top_srcdir)/src/common/list.c \
	$(top_srcdir)/src/common/error.c \
	$(top_srcdir)/src/sslutils/sslutils.c

vomsclient_cu_LDADD  = \
	$(GLOBUS_GSS_LIBS) \
	$(EXPAT_LIBS) \
	$(CPPUNIT_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/sslutils \
	-I$(top_srcdir)/src/api/ccapi \
	-I$(top_srcdir)/src/api/capi \
	-I$(top_srcdir)/src/client \
	$(GLOBUS_CFLAGS) \
	$(CPPUNIT_CFLAGS) \
	-fprofile-arcs -ftest-coverage -O0
