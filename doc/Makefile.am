
USERDOC_DIR = $(top_builddir)/doc/userdoc

SGML_INCLUDES = authors.sgml bugzilla.sgml license.sgml links.sgml

SGML = $(srcdir)/voms-proxy-init.xml \
       $(srcdir)/voms-proxy-list.xml \
       $(srcdir)/voms.xml \
       $(srcdir)/testvoms.xml \
       $(srcdir)/voms-proxy-info.xml \
       $(srcdir)/voms-proxy-destroy.xml \
       $(srcdir)/voms-install-replica.xml \
       $(srcdir)/voms-proxy-fake.xml

SGML_DIST = voms-proxy-init.xml voms.sgml testvoms.xml \
						voms-proxy-info.xml \
            voms-proxy-destroy.xml voms-install-replica.xml \
            voms-proxy-fake.xml voms-proxy-list.xml

LATEX  = $(srcdir)/software.tex $(srcdir)/capi.tex $(srcdir)/c++api.tex $(srcdir)/AC-RFC.tex

LATEX_DIST  = software.tex capi.tex c++api.tex AC-RFC.tex

SERVER_HTML = $(USERDOC_DIR)/server/html/voms.html \
              $(USERDOC_DIR)/server/html/voms_install_db.html \
              $(USERDOC_DIR)/server/html/voms_install_replica.html

SERVER_PDF  = $(USERDOC_DIR)/server/pdf/voms.pdf \
              $(USERDOC_DIR)/server/pdf/voms_install_db.pdf \
              $(USERDOC_DIR)/server/pdf/voms_install_replica.pdf

SERVER_PS   = $(USERDOC_DIR)/server/ps/voms.ps \
              $(USERDOC_DIR)/server/ps/voms_install_db.ps \
              $(USERDOC_DIR)/server/ps/voms_install_replica.ps

CLIENT_HTML = $(USERDOC_DIR)/client/html/voms-proxy-init.html \
	      $(USERDOC_DIR)/client/html/voms-proxy-list.html \
	      $(USERDOC_DIR)/client/html/voms-proxy-info.html \
	      $(USERDOC_DIR)/client/html/voms-proxy-destroy.html \
	      $(USERDOC_DIR)/client/html/voms-proxy-fake.html

CLIENT_PDF  = $(USERDOC_DIR)/client/pdf/voms-proxy-init.pdf \
	      $(USERDOC_DIR)/client/pdf/voms-proxy-info.pdf \
	      $(USERDOC_DIR)/client/pdf/voms-proxy-list.pdf \
	      $(USERDOC_DIR)/client/pdf/voms-proxy-destroy.pdf \
	      $(USERDOC_DIR)/client/pdf/voms-proxy-fake.pdf

CLIENT_PS   = $(USERDOC_DIR)/client/ps/voms-proxy-init.ps \
	      $(USERDOC_DIR)/client/ps/voms-proxy-info.ps \
	      $(USERDOC_DIR)/client/ps/voms-proxy-list.ps \
	      $(USERDOC_DIR)/client/ps/voms-proxy-destroy.ps \
	      $(USERDOC_DIR)/client/ps/voms-proxy-fake.ps

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

if BUILD_JAVA_ONLY
man_MANS =
else
if BUILD_DOCS
man_MANS = \
	voms.8 \
	voms-proxy-init.1 \
	testvoms.1 \
	voms-proxy-info.1 \
	voms-proxy-destroy.1 \
	voms-install-replica.8 \
	voms-proxy-fake.1 \
	voms-proxy-list.1
else
man_MANS = 
endif
endif

EXTRA_DIST = $(SGML_INCLUDES) $(SGML_DIST) $(LATEX_DIST)

MAINTAINERCLEANFILES = Makefile.in \
                       manpage.links \
                       manpage.refs \
                       $(man_MANS)

CLEANFILES = $(man_MANS) $(DOCS) $(SERVER) $(CLIENT) $(UTILS) *toc *aux *log

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

if BUILD_JAVA_ONLY
userdoc-local:
else
if BUILD_DOCS
userdoc-local: $(man_MANS)
else
userdoc-local:
endif
endif

userdoc-all: $(SERVER) $(CLIENT) $(UTILS) $(DOCS) $(APIPDOCS)

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

$(APIPDOCS):
	cd apidoc/api/VOMS_C_API/latex ; $(MAKE) -f Makefile pdf ps
	cd apidoc/api/VOMS_CC_API/latex ; $(MAKE) -f Makefile pdf ps

userdoc-recursive:

userdoc: userdoc-local userdoc-recursive

if BUILD_JAVA_ONLY
install-data-hook:
else
install-data-hook:
	(cd $(DESTDIR)$(mandir)/man1; \
	for file in *.1; do \
	  GZIP=$(GZIP_ENV) gzip -f $${file}; \
	done)
	(cd $(DESTDIR)$(mandir)/man8; \
	for file in *.8; do \
	  GZIP=$(GZIP_ENV) gzip -f $${file}; \
	done)
	-ln -s voms-proxy-init.1.gz    $(DESTDIR)$(mandir)/man1/edg-voms-proxy-init.1.gz
	-ln -s voms-proxy-list.1.gz    $(DESTDIR)$(mandir)/man1/edg-voms-proxy-list.1.gz
	-ln -s voms-proxy-info.1.gz    $(DESTDIR)$(mandir)/man1/edg-voms-proxy-info.1.gz
	-ln -s voms-proxy-destroy.1.gz $(DESTDIR)$(mandir)/man1/edg-voms-proxy-destroy.1.gz
	-ln -s voms-proxy-fake.1.gz    $(DESTDIR)$(mandir)/man1/edg-voms-proxy-fake.1.gz
	-ln -s voms.8.gz               $(DESTDIR)$(mandir)/man8/edg-voms.8.gz
	-ln -s voms-install-replica.8.gz $(DESTDIR)$(mandir)/man8/edg-voms-install-replica.8.gz
if ENABLE_GLITE
	-ln -s voms-proxy-init.1.gz    $(DESTDIR)$(mandir)/man1/glite-voms-proxy-init.1.gz
	-ln -s voms-proxy-list.1.gz    $(DESTDIR)$(mandir)/man1/glite-voms-proxy-list.1.gz
	-ln -s voms-proxy-info.1.gz    $(DESTDIR)$(mandir)/man1/glite-voms-proxy-info.1.gz
	-ln -s voms-proxy-destroy.1.gz $(DESTDIR)$(mandir)/man1/glite-voms-proxy-destroy.1.gz
	-ln -s voms-proxy-fake.1.gz    $(DESTDIR)$(mandir)/man1/glite-voms-proxy-fake.1.gz
	-ln -s voms.8.gz               $(DESTDIR)$(mandir)/man8/glite-voms.8.gz
	-ln -s voms-install-replica.8.gz $(DESTDIR)$(mandir)/man8/glite-voms-install-replica.8.gz
endif
endif

MAN_STYLESHEET = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

if HAVE_DOCBOOK_MAN

%.1: %.xml $(COMMON_XMLFILES)
	$(XSLTPROC) $(XSLTPROCFLAGS) $(MAN_STYLESHEET) $<

%.8: %.xml $(COMMON_XMLFILES)
	$(XSLTPROC) $(XSLTPROCFLAGS) $(MAN_STYLESHEET) $<

%.html: %.xml
	$(XSLTPROC) $(XSLTPROCFLAGS) -o $@ $(HTML_STYLESHEET) $<
endif

.PHONY: userdoc
