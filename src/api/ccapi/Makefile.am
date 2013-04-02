includedir = @includedir@/voms

if BUILD_INTERFACES
pkgconfigdir = @libdir@/pkgconfig
pkgconfig_DATA = voms-2.0.pc
endif

lib_LTLIBRARIES = libvomsapi.la

libvomsapi_la_SOURCES = \
	api_util.cc \
	voms_api.cc \
	ccval.cc \
	internal.cc \
	cinterface.cc


libvomsapi_la_CXXFLAGS = \
	$(NO_GLOBUS_FLAGS) \
	-DNOGLOBUS \
	-I$(top_srcdir)/src/include

libvomsapi_la_LDFLAGS = \
	-rpath $(libdir) \
  -version-info 1:0:0

libvomsapi_la_LIBADD = \
	$(EXPAT_LIBS) \
	$(OPENSSL_LIBS) \
	$(top_builddir)/src/replib/librep.la \
	$(top_builddir)/src/common/libutilities_nog.la \
	$(top_builddir)/src/common/libutilc_nog.la \
	$(top_builddir)/src/sslutils/libssl_utils_nog.la \
	$(top_builddir)/src/log/liblog.la\
	$(top_builddir)/src/socklib/libsock_nog.la \
	$(top_builddir)/src/ac/libattributes_nog.la



if BUILD_INTERFACES
include_HEADERS = \
	voms_api.h \
	voms_apic.h

EXTRA_DIST = \
	api_util.h \
	ccval.h \
	voms_api.h \
	voms_apic.h \
	cinterface.h \
	realdata.h \
	internal.h
endif

CLEANFILES = \
	libvomsapi.la

###

mandir     = $(datadir)/man
APIDOC_DIR = $(top_builddir)/doc/apidoc
OUTPUT_DIR = VOMS_CC_API VOMS_C_API

CCDOCPLC_DIR = $(top_builddir)/doc/apidoc/api/VOMS_CC_API
CDOCPLC_DIR = $(top_builddir)/doc/apidoc/api/VOMS_C_API

CCHTML = $(CCDOCPLC_DIR)/html/index.html
CHTML = $(CDOCPLC_DIR)/html/index.html

HTML = $(CCHTML) $(CHTML)

if BUILD_DOCS

CCMAN3 = $(CCDOCPLC_DIR)/man/man3/voms.3 \
        $(CCDOCPLC_DIR)/man/man3/voms_api.h.3 \
        $(CCDOCPLC_DIR)/man/man3/vomsdata.3

CMAN3 = $(CDOCPLC_DIR)/man/man3/voms_apic.h.3

MAN3 = $(CCMAN3) $(CMAN3)

endif

PDF   = $(CCDOCPLC_DIR)/pdf/VOMS_CC_API.pdf \
	$(CDOCPLC_DIR)/pdf/VOMS_C_API.pdf

PS    = $(CCDOCPLC_DIR)/ps/VOMS_CC_API.ps \
	$(CDOCPLC_DIR)/pdf/VOMS_C_API.ps

CCLATEX = $(CCDOCPLC_DIR)/latex/Makefile \
        $(CCDOCPLC_DIR)/latex/refman.tex \
        $(CCDOCPLC_DIR)/latex/doxygen.sty

CLATEX = $(CDOCPLC_DIR)/latex/Makefile \
        $(CDOCPLC_DIR)/latex/refman.tex \
        $(CDOCPLC_DIR)/latex/doxygen.sty

LATEX = $(CCLATEX) $(CLATEX)

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
USE_PDFLATEX           = YES\n\
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
USE_PDFLATEX           = YES\n\
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

install-exec-am: lib_LTLIBRARIES = $(INSTALL_API_LIBS)
install-exec-am: install-libLTLIBRARIES

apidoc: apidoc-local apidoc-recursive

if BUILD_DOCS
$(CCHTML): $(CCDOCPLC_DIR)/Doxyfile $(include_HEADERS)
	doxygen $(CCDOCPLC_DIR)/Doxyfile

$(CHTML): $(CDOCPLC_DIR)/Doxyfile $(include_HEADERS)
	doxygen $(CDOCPLC_DIR)/Doxyfile

$(CCMAN3) $(CCLATEX): $(CCHTML)

$(CMAN3) $(CLATEX): $(CHTML)

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
endif

if BUILD_DOCS
install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(mandir)/man3
	for file in $(MAN3); do \
	  $(INSTALL_DATA) $${file} $(DESTDIR)$(mandir)/man3; \
	done
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/grid-security/vomsdir
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/grid-security/voms
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/voms
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log/voms
	$(mkinstalldirs) $(DESTDIR)$(datadir)/voms

install-data-hook:
	(cd $(DESTDIR)$(mandir)/man3; \
	for file in *.3; do \
	  GZIP=$(GZIP_ENV) gzip -f $${file}; \
	done)
endif

clean:
	-rm -rf $(DOCPLC_DIR) *.o *.lo *.la
