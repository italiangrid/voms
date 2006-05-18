
includedir = $(prefix)/include/glite/security/voms

lib_LTLIBRARIES = \
	libvomsapi_nog.la \
	libvomsapi.la \
	libvomsc.la \
	$(WANTED_API_LIBS) # may add the libraries defined in EXTRA_LTLIBRARIES

if BUILD_JAVA
CCSOURCES = \
	api_util.cc \
	jni-int.cc \
	voms_api.cc \
	ccval.cc \
	cinterface.cc
else
CCSOURCES = \
	api_util.cc \
	voms_api.cc \
	ccval.cc \
	cinterface.cc
endif

if BUILD_JAVA
API_INCLUDES = \
	$(JAVA_INCLUDES) \
	-I$(top_srcdir)/src/include
else
API_INCLUDES = \
	-I$(top_srcdir)/src/include
endif

libvomsapi_nog_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_nog_la_CPPFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-DNOGLOBUS \
	$(API_INCLUDES)

NOGLIBADD = \
	$(EXPAT_LIBS) \
	$(OPENSSL_LIBS) \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/common/libutilities_nog.la \
	$(top_builddir)/src/common/libutilc_nog.la \
	$(top_builddir)/src/sslutils/libssl_utils_nog.la \
	$(top_builddir)/src/log/liblog.la

libvomsapi_nog_la_LIBADD = \
	$(NOGLIBADD) \
	$(top_builddir)/src/ac/libattributes_nog.la

libvomsapi_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_CFLAGS)

CCLIBADD = \
	$(EXPAT_LIBS) \
  $(GLOBUS_LIBS) \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/common/libutilities.la \
	$(top_builddir)/src/log/liblog.la

libvomsapi_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock.la \
	$(top_builddir)/src/ac/libccattcert.la

if BUILD_JAVA
CSOURCES = \
	api_util.cc \
	voms_api.cc \
	ccval.cc \
	jni-int.cc \
	cinterface.cc
else
CSOURCES = \
	api_util.cc \
	voms_api.cc \
	ccval.cc \
	cinterface.cc
endif

libvomsc_la_SOURCES = \
	$(CSOURCES)

libvomsc_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_CFLAGS)

CLIBADD = 
	$(top_builddir)/src/common/libutilities.la \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/log/liblog.la

libvomsc_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock.la \
	$(top_builddir)/src/ac/libccattcert.la

# test programs

noinst_PROGRAMS = test ctest
test_SOURCES = test.cc
test_LDADD = libvomsapi.la
test_CPPFLAGS = -I$(top_srcdir)/src/include $(GLOBUS_CFLAGS)
ctest_SOURCES = ctest.c
ctest_LDADD = libvomsc.la
ctest_CPPFLAGS = -I$(top_srcdir)/src/include $(GLOBUS_CFLAGS)

EXTRA_LTLIBRARIES = \
	libvomsapi_gcc32.la \
	libvomsapi_gcc32dbg.la \
	libvomsapi_gcc32pthr.la \
	libvomsapi_gcc32dbgpthr.la \
	libvomsapi_gcc64.la \
	libvomsapi_gcc64dbg.la \
	libvomsapi_gcc64pthr.la \
	libvomsapi_gcc64dbgpthr.la \
	libvomsc_gcc32.la \
	libvomsc_gcc32dbg.la \
	libvomsc_gcc32pthr.la \
	libvomsc_gcc32dbgpthr.la \
	libvomsc_gcc64.la \
	libvomsc_gcc64dbg.la \
	libvomsc_gcc64pthr.la \
	libvomsc_gcc64dbgpthr.la

libvomsapi_gcc32_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_gcc32_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_GCC_CFLAGS)

libvomsapi_gcc32_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc32.la \
	$(top_builddir)/src/ac/libccattcert_gcc32.la

libvomsapi_gcc32_la_LDFLAGS = \
	-rpath $(libdir)

libvomsapi_gcc32dbg_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_gcc32dbg_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(GLOBUS_GCC32DBG_CFLAGS) \
	$(API_INCLUDES)

libvomsapi_gcc32dbg_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc32dbg.la \
	$(top_builddir)/src/ac/libccattcert_gcc32dbg.la

libvomsapi_gcc32dbg_la_LDFLAGS = \
	-rpath $(libdir)

libvomsapi_gcc32pthr_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_gcc32pthr_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_GCC32PTHR_CFLAGS)

libvomsapi_gcc32pthr_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc32pthr.la \
	$(top_builddir)/src/ac/libccattcert_gcc32pthr.la

libvomsapi_gcc32pthr_la_LDFLAGS = \
	-rpath $(libdir)

libvomsapi_gcc32dbgpthr_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_gcc32dbgpthr_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_GCC32DBGPTHR_CFLAGS)

libvomsapi_gcc32dbgpthr_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc32dbgpthr.la \
	$(top_builddir)/src/ac/libccattcert_gcc32dbgpthr.la

libvomsapi_gcc32dbgpthr_la_LDFLAGS = \
	-rpath $(libdir)

libvomsc_gcc32_la_SOURCES = \
	$(CSOURCES)

libvomsc_gcc32_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_CFLAGS)

libvomsc_gcc32_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc32.la \
	$(top_builddir)/src/ac/libccattcert_gcc32.la

libvomsc_gcc32_la_LDFLAGS = \
	-rpath $(libdir)

libvomsc_gcc32dbg_la_SOURCES = \
	$(CSOURCES)

libvomsc_gcc32dbg_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_CFLAGS)

libvomsc_gcc32dbg_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc32dbg.la \
	$(top_builddir)/src/ac/libccattcert_gcc32dbg.la

libvomsc_gcc32dbg_la_LDFLAGS = \
	-rpath $(libdir)

libvomsc_gcc32pthr_la_SOURCES = \
	$(CSOURCES)

libvomsc_gcc32pthr_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_CFLAGS)

libvomsc_gcc32pthr_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc32pthr.la \
	$(top_builddir)/src/ac/libccattcert_gcc32pthr.la

libvomsc_gcc32pthr_la_LDFLAGS = \
	-rpath $(libdir)

libvomsc_gcc32dbgpthr_la_SOURCES = \
	$(CSOURCES)

libvomsc_gcc32dbgpthr_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_CFLAGS)

libvomsc_gcc32dbgpthr_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc32dbgpthr.la \
	$(top_builddir)/src/ac/libccattcert_gcc32dbgpthr.la

libvomsc_gcc32dbgpthr_la_LDFLAGS = \
	-rpath $(libdir)




libvomsapi_gcc64_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_gcc64_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_GCC64_CFLAGS)

libvomsapi_gcc64_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc64.la \
	$(top_builddir)/src/ac/libccattcert_gcc64.la

libvomsapi_gcc64_la_LDFLAGS = \
	-rpath $(libdir)

libvomsapi_gcc64dbg_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_gcc64dbg_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_GCC64DBG_CFLAGS)

libvomsapi_gcc64dbg_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc64dbg.la \
	$(top_builddir)/src/ac/libccattcert_gcc64dbg.la

libvomsapi_gcc64dbg_la_LDFLAGS = \
	-rpath $(libdir)

libvomsapi_gcc64pthr_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_gcc64pthr_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_GCC64PTHR_CFLAGS)

libvomsapi_gcc64pthr_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc64pthr.la \
	$(top_builddir)/src/ac/libccattcert_gcc64pthr.la

libvomsapi_gcc64pthr_la_LDFLAGS = \
	-rpath $(libdir)

libvomsapi_gcc64dbgpthr_la_SOURCES = \
	$(CCSOURCES)

libvomsapi_gcc64dbgpthr_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_GCC64DBGPTHR_CFLAGS)

libvomsapi_gcc64dbgpthr_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc64dbgpthr.la \
	$(top_builddir)/src/ac/libccattcert_gcc64dbgpthr.la

libvomsapi_gcc64dbgpthr_la_LDFLAGS = \
	-rpath $(libdir)

libvomsc_gcc64_la_SOURCES = \
	$(CSOURCES)

libvomsc_gcc64_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(GLOBUS_CFLAGS)

libvomsc_gcc64_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc64.la \
	$(top_builddir)/src/ac/libccattcert_gcc64.la

libvomsc_gcc64_la_LDFLAGS = \
	-rpath $(libdir)

libvomsc_gcc64dbg_la_SOURCES = \
	$(CSOURCES)

libvomsc_gcc64dbg_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_CFLAGS)

libvomsc_gcc64dbg_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc64dbg.la \
	$(top_builddir)/src/ac/libccattcert_gcc64dbg.la

libvomsc_gcc64dbg_la_LDFLAGS = \
	-rpath $(libdir)

libvomsc_gcc64pthr_la_SOURCES = \
	$(CSOURCES)

libvomsc_gcc64pthr_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_CFLAGS)

libvomsc_gcc64pthr_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc64pthr.la \
	$(top_builddir)/src/ac/libccattcert_gcc64pthr.la


libvomsc_gcc64pthr_la_LDFLAGS = \
	-rpath $(libdir)

libvomsc_gcc64dbgpthr_la_SOURCES = \
	$(CSOURCES)

libvomsc_gcc64dbgpthr_la_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(API_INCLUDES) \
	$(GLOBUS_CFLAGS)

libvomsc_gcc64dbgpthr_la_LIBADD = \
	$(CCLIBADD) \
	$(top_builddir)/src/socklib/libsock_gcc64dbgpthr.la \
	$(top_builddir)/src/ac/libccattcert_gcc64dbgpthr.la

libvomsc_gcc64dbgpthr_la_LDFLAGS = \
	-rpath $(libdir)

include_HEADERS = \
	voms_api.h \
	voms_apic.h \
	voms_api_nog.h \
	voms_apic_nog.h

EXTRA_DIST = \
	api_util.h \
	ccval.h \
	voms_api.h \
	voms_apic.h \
	cinterface.h \
	jni-int.h \
  ctest.c

CLEANFILES = \
	libvomsapi_gcc32.la \
	libvomsapi_gcc32dbg.la \
	libvomsapi_gcc32pthr.la \
	libvomsapi_gcc32dbgpthr.la \
	libvomsapi_gcc64.la \
	libvomsapi_gcc64dbg.la \
	libvomsapi_gcc64pthr.la \
	libvomsapi_gcc64dbgpthr.la \
	libvomsapi_gcc32.la \
	libvomsapi_gcc32dbg.la \
	libvomsapi_gcc32pthr.la \
	libvomsapi_gcc32dbgpthr.la \
	libvomsc_gcc32.la \
	libvomsc_gcc32dbg.la \
	libvomsc_gcc32pthr.la \
	libvomsc_gcc32dbgpthr.la

###

mandir     = $(datadir)/man
APIDOC_DIR = $(top_builddir)/doc/apidoc
OUTPUT_DIR = VOMS_CC_API VOMS_C_API

CCDOCPLC_DIR = $(top_builddir)/doc/apidoc/api/VOMS_CC_API
CDOCPLC_DIR = $(top_builddir)/doc/apidoc/api/VOMS_C_API

HTML  = $(CCDOCPLC_DIR)/html/index.html
				$(CDOCPLC_DIR)/html/index.html

if BUILD_DOCS
MAN3  = $(CCDOCPLC_DIR)/man/man3/data.3 \
        $(CCDOCPLC_DIR)/man/man3/voms.3 \
        $(CCDOCPLC_DIR)/man/man3/voms_api.h.3 \
        $(CCDOCPLC_DIR)/man/man3/vomsdata.3 \
				$(CDOCPLC_DIR)/man/man3/voms_apic.h.3
endif

PDF   = $(CCDOCPLC_DIR)/pdf/VOMS_CC_API.pdf \
				$(CDOCPLC_DIR)/pdf/VOMS_C_API.pdf

PS    = $(CCDOCPLC_DIR)/ps/VOMS_CC_API.ps \
				$(CDOCPLC_DIR)/pdf/VOMS_C_API.ps

LATEX = $(CCDOCPLC_DIR)/latex/Makefile \
        $(CCDOCPLC_DIR)/latex/refman.tex \
        $(CCDOCPLC_DIR)/latex/doxygen.sty \
				$(CDOCPLC_DIR)/latex/Makefile \
        $(CDOCPLC_DIR)/latex/refman.tex \
        $(CDOCPLC_DIR)/latex/doxygen.sty

DOXY = $(CCDOCPLC_DIR)/Doxyfile $(CDOCPLC_DIR)/Doxyfile $(include_HEADERS)

$(CCDOCPLC_DIR)/Doxyfile:
	-mkdir -p $(CCDOCPLC_DIR)
	echo -e "INPUT                  = $(top_srcdir)/src/api/ccapi/voms_api.h\n\
OUTPUT_DIRECTORY       = \"$(top_builddir)/doc/apidoc/api/VOMS_CC_API\"\n\
PROJECT_NAME           = \"VOMS CC API\"\n\
PROJECT_NUMBER         = \"1.5.0\"\n\
OUTPUT_LANGUAGE        = English\n\
EXTRACT_ALL            = YES\n\
EXTRACT_STATIC         = YES\n\
EXTRACT_LOCAL_CLASSES  = YES\n\
ALWAYS_DETAILED_SEC    = NO\n\
INLINE_INHERITED_MEMB  = NO\n\
FULL_PATH_NAMES        = NO\n\
CASE_SENSE_NAMES       = YES\n\
JAVADOC_AUTOBRIEF      = NO\n\
DISTRIBUTE_GROUP_DOC   = NO\n\
TAB_SIZE               = 8\n\
GENERATE_TODOLIST      = YES\n\
GENERATE_TESTLIST      = YES\n\
GENERATE_BUGLIST       = YES\n\
MAX_INITIALIZER_LINES  = 30\n\
OPTIMIZE_OUTPUT_FOR_C  = YES\n\
SHOW_USED_FILES        = YES\n\
WARNINGS               = YES\n\
WARN_IF_UNDOCUMENTED   = YES\n\
WARN_FORMAT            = \"\044file:\044line: \044text\"\n\
FILE_PATTERNS          = *.h\n\
EXCLUDE                = CVS\n\
EXCLUDE_SYMLINKS       = NO\n\
FILTER_SOURCE_FILES    = NO\n\
SOURCE_BROWSER         = YES\n\
INLINE_SOURCES         = NO\n\
ALPHABETICAL_INDEX     = NO\n\
GENERATE_HTML          = YES\n\
HTML_OUTPUT            = html\n\
HTML_FILE_EXTENSION    = .html\n\
HTML_ALIGN_MEMBERS     = YES\n\
GENERATE_HTMLHELP      = NO\n\
GENERATE_CHI           = NO\n\
BINARY_TOC             = NO\n\
TOC_EXPAND             = NO\n\
ENUM_VALUES_PER_LINE   = 4\n\
GENERATE_TREEVIEW      = NO\n\
GENERATE_LATEX         = YES\n\
COMPACT_LATEX          = NO\n\
PDF_HYPERLINKS         = YES\n\
USE_PDFLATEX           = NO\n\
LATEX_BATCHMODE        = YES\n\
GENERATE_RTF           = NO\n\
GENERATE_MAN           = YES\n\
MAN_LINKS              = NO\n\
GENERATE_XML           = NO\n\
CLASS_DIAGRAMS         = YES\n\
HAVE_DOT               = NO\n\
CLASS_GRAPH            = YES\n\
COLLABORATION_GRAPH    = YES\n\
TEMPLATE_RELATIONS     = YES\n\
HIDE_UNDOC_RELATIONS   = YES\n\
INCLUDE_GRAPH          = YES\n\
INCLUDED_BY_GRAPH      = YES\n\
GRAPHICAL_HIERARCHY    = YES\n\
DOT_IMAGE_FORMAT       = png\n\
MAX_DOT_GRAPH_WIDTH    = 1024\n\
MAX_DOT_GRAPH_HEIGHT   = 1024" >$(CCDOCPLC_DIR)/Doxyfile

$(CDOCPLC_DIR)/Doxyfile:
	-mkdir -p $(CDOCPLC_DIR)
	echo -e "INPUT                  = $(top_srcdir)/src/api/ccapi/voms_apic.h\n\
OUTPUT_DIRECTORY       = \"$(top_builddir)/doc/apidoc/api/VOMS_C_API\"\n\
PROJECT_NAME           = \"VOMS C API\"\n\
PROJECT_NUMBER         = \"1.5.0\"\n\
OUTPUT_LANGUAGE        = English\n\
EXTRACT_ALL            = YES\n\
EXTRACT_STATIC         = YES\n\
EXTRACT_LOCAL_CLASSES  = YES\n\
ALWAYS_DETAILED_SEC    = NO\n\
INLINE_INHERITED_MEMB  = NO\n\
FULL_PATH_NAMES        = NO\n\
CASE_SENSE_NAMES       = YES\n\
JAVADOC_AUTOBRIEF      = NO\n\
DISTRIBUTE_GROUP_DOC   = NO\n\
TAB_SIZE               = 8\n\
GENERATE_TODOLIST      = YES\n\
GENERATE_TESTLIST      = YES\n\
GENERATE_BUGLIST       = YES\n\
MAX_INITIALIZER_LINES  = 30\n\
OPTIMIZE_OUTPUT_FOR_C  = YES\n\
SHOW_USED_FILES        = YES\n\
WARNINGS               = YES\n\
WARN_IF_UNDOCUMENTED   = YES\n\
WARN_FORMAT            = \"\044file:\044line: \044text\"\n\
FILE_PATTERNS          = *.h\n\
EXCLUDE                = CVS\n\
EXCLUDE_SYMLINKS       = NO\n\
FILTER_SOURCE_FILES    = NO\n\
SOURCE_BROWSER         = YES\n\
INLINE_SOURCES         = NO\n\
ALPHABETICAL_INDEX     = NO\n\
GENERATE_HTML          = YES\n\
HTML_OUTPUT            = html\n\
HTML_FILE_EXTENSION    = .html\n\
HTML_ALIGN_MEMBERS     = YES\n\
GENERATE_HTMLHELP      = NO\n\
GENERATE_CHI           = NO\n\
BINARY_TOC             = NO\n\
TOC_EXPAND             = NO\n\
ENUM_VALUES_PER_LINE   = 4\n\
GENERATE_TREEVIEW      = NO\n\
GENERATE_LATEX         = YES\n\
COMPACT_LATEX          = NO\n\
PDF_HYPERLINKS         = YES\n\
USE_PDFLATEX           = NO\n\
LATEX_BATCHMODE        = YES\n\
GENERATE_RTF           = NO\n\
GENERATE_MAN           = YES\n\
MAN_LINKS              = NO\n\
GENERATE_XML           = NO\n\
CLASS_DIAGRAMS         = YES\n\
HAVE_DOT               = NO\n\
CLASS_GRAPH            = YES\n\
COLLABORATION_GRAPH    = YES\n\
TEMPLATE_RELATIONS     = YES\n\
HIDE_UNDOC_RELATIONS   = YES\n\
INCLUDE_GRAPH          = YES\n\
INCLUDED_BY_GRAPH      = YES\n\
GRAPHICAL_HIERARCHY    = YES\n\
DOT_IMAGE_FORMAT       = png\n\
MAX_DOT_GRAPH_WIDTH    = 1024\n\
MAX_DOT_GRAPH_HEIGHT   = 1024" >$(CDOCPLC_DIR)/Doxyfile

maintainer-clean-local:
	-rm -rf $(OUTPUT_DIR)

all-local: apidoc-local

if BUILD_DOCS
apidoc-local: $(HTML) $(MAN3) 
else
apidoc-local:
endif

apidoc-recursive:
#	$(MAKE) apidoc -C capi

apidoc: apidoc-local apidoc-recursive

if BUILD_DOCS
$(MAN3) $(HTML) $(LATEX): $(DOXY)
	doxygen $(CCDOCPLC_DIR)/Doxyfile
	doxygen $(CDOCPLC_DIR)/Doxyfile


#$(OUTPUT_DIR)/man/man3/%.3: $(DOXY)
#	doxygen

$(PDF): $(LATEX)
	cd $(CCDOCPLC_DIR)/latex; \
	pdflatex refman.tex; \
	pdflatex refman.tex; \
	pdflatex refman.tex; \
	pdflatex refman.tex;
	cd $(CDOCPLC_DIR)/latex; \
	pdflatex refman.tex; \
	pdflatex refman.tex; \
	pdflatex refman.tex; \
	pdflatex refman.tex;

#	cd ../..; \
#	$(mkinstalldirs) $(OUTPUT_DIR)/pdf; \
#	$(INSTALL_DATA) $(OUTPUT_DIR)/latex/refman.pdf $(PDF);

$(PS): $(LATEX)
	cd $(CCDOCPLC_DIR)/latex; \
	latex refman.tex; \
	latex refman.tex; \
	latex refman.tex; \
	latex refman.tex; \
	dvips -f <refman.dvi >refman.ps; 
	cd $(CDOCPLC_DIR)/latex; \
	latex refman.tex; \
	latex refman.tex; \
	latex refman.tex; \
	latex refman.tex; \
	dvips -f <refman.dvi >refman.ps; 
#	cd ../..; \
#	$(mkinstalldirs) $(OUTPUT_DIR)/ps; \
#	$(INSTALL_DATA) $(OUTPUT_DIR)/latex/refman.ps $(PS);

endif

if BUILD_DOCS
install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(mandir)/man3
	for file in $(MAN3); do \
	  $(INSTALL_DATA) $${file} $(DESTDIR)$(mandir)/man3; \
	done

install-data-hook:
	(cd $(DESTDIR)$(mandir)/man3; \
	for file in *.3; do \
	  GZIP=$(GZIP_ENV) gzip -f $${file}; \
	done)
endif

clean:
	-rm -rf $(DOCPLC_DIR) *.o *.lo *.la
