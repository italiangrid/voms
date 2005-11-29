
USERDOC_DIR = $(top_builddir)/doc/userdoc

SGML_INCLUDES = authors.sgml bugzilla.sgml license.sgml links.sgml

SGML = $(srcdir)/edg-voms-proxy-init.sgml \
			 $(srcdir)/edg-voms-proxy-list.sgml \
			 $(srcdir)/edg-voms.sgml \
	     $(srcdir)/testvoms.sgml 
			 $(srcdir)/voms_install_db.sgml \
       $(srcdir)/edg-voms-proxy-info.sgml \
       $(srcdir)/edg-voms-proxy-destroy.sgml \
	     $(srcdir)/voms_install_replica.sgml \
	     $(srcdir)/edg-voms-proxy-fake.sgml

SGML_DIST = edg-voms-proxy-init.sgml edg-voms.sgml testvoms.sgml \
            voms_install_db.sgml edg-voms-proxy-info.sgml \
	          edg-voms-proxy-destroy.sgml voms_install_replica.sgml \
	          edg-voms-proxy-fake.sgml edg-voms-proxy-list.sgml

LATEX  = $(srcdir)/software.tex $(srcdir)/capi.tex $(srcdir)/c++api.tex $(srcdir)/AC-RFC.tex

LATEX_DIST  = software.tex capi.tex c++api.tex AC-RFC.tex

SERVER_HTML = $(USERDOC_DIR)/server/html/edg-voms.html \
              $(USERDOC_DIR)/server/html/voms_install_db.html \
              $(USERDOC_DIR)/server/html/voms_install_replica.html

SERVER_PDF  = $(USERDOC_DIR)/server/pdf/edg-voms.pdf \
              $(USERDOC_DIR)/server/pdf/voms_install_db.pdf \
              $(USERDOC_DIR)/server/pdf/voms_install_replica.pdf

SERVER_PS   = $(USERDOC_DIR)/server/ps/edg-voms.ps \
              $(USERDOC_DIR)/server/ps/voms_install_db.ps \
              $(USERDOC_DIR)/server/ps/voms_install_replica.ps

CLIENT_HTML = $(USERDOC_DIR)/client/html/edg-voms-proxy-init.html \
	      $(USERDOC_DIR)/client/html/edg-voms-proxy-list.html \
	      $(USERDOC_DIR)/client/html/edg-voms-proxy-info.html \
	      $(USERDOC_DIR)/client/html/edg-voms-proxy-destroy.html \
	      $(USERDOC_DIR)/client/html/edg-voms-proxy-fake.html

CLIENT_PDF  = $(USERDOC_DIR)/client/pdf/edg-voms-proxy-init.pdf \
	      $(USERDOC_DIR)/client/pdf/edg-voms-proxy-info.pdf \
	      $(USERDOC_DIR)/client/pdf/edg-voms-proxy-list.pdf \
	      $(USERDOC_DIR)/client/pdf/edg-voms-proxy-destroy.pdf \
	      $(USERDOC_DIR)/client/pdf/edg-voms-proxy-fake.pdf

CLIENT_PS   = $(USERDOC_DIR)/client/ps/edg-voms-proxy-init.ps \
	      $(USERDOC_DIR)/client/ps/edg-voms-proxy-info.ps \
	      $(USERDOC_DIR)/client/ps/edg-voms-proxy-list.ps \
	      $(USERDOC_DIR)/client/ps/edg-voms-proxy-destroy.ps \
	      $(USERDOC_DIR)/client/ps/edg-voms-proxy-fake.ps

UTILS_HTML  = $(USERDOC_DIR)/utils/html/testvoms.html

UTILS_PDF   = $(USERDOC_DIR)/utils/pdf/testvoms.pdf

UTILS_PS    = $(USERDOC_DIR)/utils/ps/testvoms.ps

SERVER = $(SERVER_HTML) \
         $(SERVER_PDF) \
         $(SERVER_PS)

CLIENT = $(CLIENT_HTML) \
         $(CLIENT_PDF) \
         $(CLIENT_PS)

UTILS  = $(UTILS_HTML) \
         $(UTILS_PDF) \
         $(UTILS_PS)

DOCS   = capi.pdf c++api.pdf software.pdf AC-RFC.pdf

mandir = $(datadir)/man

if BUILD_DOCS
man_MANS = \
	edg-voms.8 \
	edg-voms-proxy-init.1 \
	testvoms.1 \
	voms_install_db.1 \
	edg-voms-proxy-info.1 \
	edg-voms-proxy-destroy.1 \
	voms_install_replica.1 \
	edg-voms-proxy-fake.1 \
	edg-voms-proxy-list.1
else
man_MANS = 
endif

EXTRA_DIST = $(SGML_INCLUDES) $(SGML_DIST) $(LATEX_DIST)

MAINTAINERCLEANFILES = Makefile.in \
                       aclocal.m4 \
                       manpage.links \
                       manpage.refs \
                       $(man_MANS)

CLEANFILES = $(man_MANS) $(DOCS) $(SERVER) $(CLIENT) $(UTILS)

$(USERDOC_DIR)/server/html/%.html: %.sgml $(SGML_INCLUDES)
	echo $(USERDOC_DIR)/
	echo $(mandir)
	echo $(DESTDIR)
	$(mkinstalldirs) $(USERDOC_DIR)/server
	docbook2html --output $(USERDOC_DIR)/server/html --nochunks $<

$(USERDOC_DIR)/server/pdf/%.pdf: %.sgml $(SGML_INCLUDES)
	$(mkinstalldirs) $(USERDOC_DIR)/server
	docbook2pdf --output $(USERDOC_DIR)/server/pdf $<

$(USERDOC_DIR)/server/ps/%.ps: %.sgml $(SGML_INCLUDES)
	$(mkinstalldirs) $(USERDOC_DIR)/server
	docbook2ps --output $(USERDOC_DIR)/server/ps $<

$(USERDOC_DIR)/client/html/%.html: %.sgml $(SGML_INCLUDES)
	$(mkinstalldirs) $(USERDOC_DIR)/client
	docbook2html --output $(USERDOC_DIR)/client/html --nochunks $<

$(USERDOC_DIR)/client/pdf/%.pdf: %.sgml $(SGML_INCLUDES)
	$(mkinstalldirs) $(USERDOC_DIR)/client
	docbook2pdf --output $(USERDOC_DIR)/client/pdf $<

$(USERDOC_DIR)/client/ps/%.ps: %.sgml $(SGML_INCLUDES)
	$(mkinstalldirs) $(USERDOC_DIR)/client
	docbook2ps --output $(USERDOC_DIR)/client/ps $<

$(USERDOC_DIR)/utils/html/%.html: %.sgml $(SGML_INCLUDES)
	$(mkinstalldirs) $(USERDOC_DIR)/utils
	docbook2html --output $(USERDOC_DIR)/utils/html --nochunks $<

$(USERDOC_DIR)/utils/pdf/%.pdf: %.sgml $(SGML_INCLUDES)
	$(mkinstalldirs) $(USERDOC_DIR)/utils
	docbook2pdf --output $(USERDOC_DIR)/utils/pdf $<

$(USERDOC_DIR)/utils/ps/%.ps: %.sgml $(SGML_INCLUDES)
	$(mkinstalldirs) $(USERDOC_DIR)/utils
	docbook2ps --output $(USERDOC_DIR)/utils/ps $<

%.1: %.sgml $(SGML_INCLUDES)
	docbook2man $<

%.8: %.sgml $(SGML_INCLUDES)
	docbook2man $<

%.pdf: %.tex
	pdflatex $<
	pdflatex $<
	pdflatex $<

%.dvi: %.tex
	latex $<
	latex $<
	latex $<

maintainer-clean-local:
	-rm -rf $(USERDOC_DIR)

all-local: userdoc-local

APIPDOCS = apidoc/api/VOMS_C_API/latex/refman.pdf \
	apidoc/api/VOMS_C_API/latex/refman.ps \
	apidoc/api/VOMS_CC_API/latex/refman.pdf \
	apidoc/api/VOMS_CC_API/latex/refman.ps

if BUILD_DOCS
userdoc-local: $(SERVER) $(CLIENT) $(UTILS) $(DOCS) $(APIPDOCS)
else
userdoc-local:
endif

$(APIPDOCS):
	cd apidoc/api/VOMS_C_API/latex ; $(MAKE) -f Makefile pdf ps
	cd apidoc/api/VOMS_CC_API/latex ; $(MAKE) -f Makefile pdf ps

userdoc-recursive:

userdoc: userdoc-local userdoc-recursive

if BUILD_DOCS
install-data-hook:
	(cd $(DESTDIR)$(mandir)/man1; \
	for file in *.1; do \
	  GZIP=$(GZIP_ENV) gzip -f $${file}; \
	done)
	(cd $(DESTDIR)$(mandir)/man8; \
	for file in *.8; do \
	  GZIP=$(GZIP_ENV) gzip -f $${file}; \
	done)
	$(mkinstalldirs) $(DESTDIR)/$(datadir)/doc/voms$(DOCVER)
	cp software.pdf capi.pdf c++api.pdf AC-RFC.pdf $(DESTDIR)/$(datadir)/doc/voms$(DOCVER)
	cp apidoc/api/VOMS_CC_API/latex/refman.pdf $(DESTDIR)/$(datadir)/doc/voms$(DOCVER)/VOMS_CC_API.pdf
	cp apidoc/api/VOMS_CC_API/latex/refman.ps $(DESTDIR)/$(datadir)/doc/voms$(DOCVER)/VOMS_CC_API.ps
	cp apidoc/api/VOMS_C_API/latex/refman.pdf $(DESTDIR)/$(datadir)/doc/voms$(DOCVER)/VOMS_C_API.pdf
	cp apidoc/api/VOMS_C_API/latex/refman.ps $(DESTDIR)/$(datadir)/doc/voms$(DOCVER)/VOMS_C_API.ps
	-ln -s edg-voms-proxy-init.1.gz    $(DESTDIR)$(mandir)/man1/voms-proxy-init.1.gz
	-ln -s edg-voms-proxy-list.1.gz    $(DESTDIR)$(mandir)/man1/voms-proxy-list.1.gz
	-ln -s edg-voms-proxy-info.1.gz    $(DESTDIR)$(mandir)/man1/voms-proxy-info.1.gz
	-ln -s edg-voms-proxy-destroy.1.gz $(DESTDIR)$(mandir)/man1/voms-proxy-destroy.1.gz
	-ln -s edg-voms-proxy-fake.1.gz $(DESTDIR)$(mandir)/man1/voms-proxy-fake.1.gz
	-ln -s edg-voms.8.gz               $(DESTDIR)$(mandir)/man8/voms.8.gz
else
install-data-hook:
endif

.PHONY: userdoc
