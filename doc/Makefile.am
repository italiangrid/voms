SGML_INCLUDES = authors.sgml bugzilla.sgml license.sgml links.sgml

SGML = $(srcdir)/voms-proxy-init.xml \
       $(srcdir)/voms-proxy-list.xml \
       $(srcdir)/voms.xml \
       $(srcdir)/voms-proxy-info.xml \
       $(srcdir)/voms-proxy-destroy.xml \
       $(srcdir)/voms-proxy-fake.xml

SGML_DIST = voms-proxy-init.xml voms.xml voms-proxy-info.xml \
            voms-proxy-destroy.xml \
            voms-proxy-fake.xml voms-proxy-list.xml

LATEX_DIST  = software.tex capi.tex c++api.tex AC-RFC.tex

mandir = $(datadir)/man

if BUILD_SERVER 
if BUILD_CLIENTS
man_MANS = \
	voms.8 \
	voms-proxy-init.1 \
	voms-proxy-info.1 \
	voms-proxy-destroy.1 \
	voms-proxy-fake.1 \
	voms-proxy-list.1
endif
endif

if BUILD_SERVER
if !BUILD_CLIENTS
man_MANS = \
	voms.8 
endif
endif

if !BUILD_SERVER
if BUILD_CLIENTS
man_MANS = \
	voms-proxy-init.1 \
	voms-proxy-info.1 \
	voms-proxy-destroy.1 \
	voms-proxy-fake.1 \
	voms-proxy-list.1
endif
endif

if !BUILD_SERVER
if !BUILD_CLIENTS
man_MANS =
endif
endif

EXTRA_DIST = $(SGML_INCLUDES) $(SGML_DIST) $(LATEX_DIST) $(man_MANS)

MAINTAINERCLEANFILES = Makefile.in \
                       manpage.links \
                       manpage.refs

CLEANFILES = $(DOCS) *toc *aux *log

maintainer-clean-local:
	-rm -rf $(USERDOC_DIR)

all-local: userdoc-local

if BUILD_DOCS
userdoc-local: $(man_MANS)
else
userdoc-local:
endif

userdoc: userdoc-local

install-data-hook: install-man1 install-man8


MAN_STYLESHEET = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

if BUILD_DOCS
if HAVE_DOCBOOK_MAN

%.1: %.xml $(COMMON_XMLFILES)
	$(XSLTPROC) $(XSLTPROCFLAGS) $(MAN_STYLESHEET) $<

%.8: %.xml $(COMMON_XMLFILES)
	$(XSLTPROC) $(XSLTPROCFLAGS) $(MAN_STYLESHEET) $<

%.html: %.xml
	$(XSLTPROC) $(XSLTPROCFLAGS) -o $@ $(HTML_STYLESHEET) $<
endif
else
%1: %.xml
	touch $@

%8: %.xml
	touch $@
endif
.PHONY: userdoc
