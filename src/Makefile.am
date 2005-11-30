
SUBDIRS = \
	include \
	replib \
	sslutils \
	log \
	common \
	socklib \
	ac \
	api \
	utils \
	client \
	server \
	install \
	replica \
	support

APIDOC_DIR = $(top_builddir)/doc/apidoc
USERDOC_DIR = $(top_builddir)/doc/userdoc

APIDOC_FILES = $(top_srcdir)/AUTHORS $(top_srcdir)/INSTALL $(top_srcdir)/LICENSE $(top_srcdir)/README
USERDOC_FILES = $(APIDOC_FILES)

all-local: apidoc-local userdoc-local

apidoc-local: $(APIDOC_FILES)
	$(mkinstalldirs) $(APIDOC_DIR)
	for file in $(APIDOC_FILES); do \
	  $(INSTALL_DATA) $${file} $(APIDOC_DIR); \
	done

apidoc-recursive:
	$(MAKE) apidoc -C api

apidoc: apidoc-local apidoc-recursive

userdoc-local: $(USERDOC_FILES)
	$(mkinstalldirs) $(USERDOC_DIR)
	for file in $(USERDOC_FILES); do \
	  $(INSTALL_DATA) $${file} $(USERDOC_DIR); \
	done

userdoc-recursive:
	$(MAKE) userdoc -C doc

userdoc: userdoc-local userdoc-recursive

install-data-local:
if BUILD_DOCS
	for subpackage in api; do \
	  $(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER); \
	  for project in VOMS_CC_API VOMS_C_API; do \
	    $(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER)/$${project}/html; \
	    $(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER)/$${project}/pdf; \
	    $(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER)/$${project}/ps; \
	    for file in $(APIDOC_DIR)/$${subpackage}/$${project}//html/*; do \
	      $(INSTALL_DATA) $${file} $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER)/$${project}/html; \
	    done; \
	    $(INSTALL_DATA) $(APIDOC_DIR)/$${subpackage}/$${project}/latex/refman.pdf $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER)/$${project}/pdf/$${project}.pdf; \
	    $(INSTALL_DATA) $(APIDOC_DIR)/$${subpackage}/$${project}/latex/refman.ps $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER)/$${project}/ps/$${project}.ps; \
	  done; \
	done; \
	for subpackage in server client utils; do \
	  $(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER); \
	  for file in $(USERDOC_FILES); do \
	    $(INSTALL_DATA) $${file} $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER); \
	  done; \
	  for dir in html pdf ps; do \
	    $(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER)/$${dir}; \
	    for file in $(USERDOC_DIR)/$${subpackage}/$${dir}/*; do \
	      $(INSTALL_DATA) $${file} $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$${subpackage}$(GCCVER)$(DOCVER)/$${dir}; \
	    done; \
	  done; \
	done
	for file in $(APIDOC_FILES); do \
	   $(INSTALL_DATA) $${file} $(DESTDIR)$(datadir)/doc/$(PACKAGE)-api$(GCCVER)$(DOCVER); \
	done;
endif
