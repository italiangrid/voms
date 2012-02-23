ACLOCAL_AMFLAGS=-I m4
SUBDIRS = src doc m4 testsuite

EXTRA_DIST = autogen.sh LICENSE

APIDOC_DIR = $(top_builddir)/doc/apidoc
USERDOC_DIR = $(top_builddir)/doc/userdoc

APIDOC_FILES = $(top_srcdir)/AUTHORS $(top_srcdir)/INSTALL $(top_srcdir)/LICENSE $(top_srcdir)/README
USERDOC_FILES = $(APIDOC_FILES)

spec=spec/voms-all.spec
deb_comp="libvomsapi1 voms-dev voms-clients voms-server"

rpmbuild_dir=@WORKDIR@/rpmbuild
debbuild_dir=@WORKDIR@/debbuild

stage_dir=dist

all-local: apidoc-local

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


gtags:
	rm -f G*; gtags

tags:
	rm -f TAGS; find . '(' '(' -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.cc' ')' -a -not -path '*/test/*' ')' -exec etags -a '{}' ';'

clean-local:
	rm -rf $(rpmbuild_dir) $(debbuild_dir) $(distdir).tar.gz dist

distclean-local: 
	rm -f configure aclocal.m4 $(distdir).tar.gz 
	rm -f m4/libtool.m4 m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4
	rm -rf autom4te.cache aux src/autogen $(rpmbuild_dir) $(debbuild_dir)
	rm -rf testsuite/dbg.log
	find . -name Makefile.in -exec rm {} \;


rpm: dist
	mkdir -p $(rpmbuild_dir)/BUILD $(rpmbuild_dir)/RPMS $(rpmbuild_dir)/SOURCES $(rpmbuild_dir)/SPECS $(rpmbuild_dir)/SRPMS
	cp $(distdir).tar.gz $(rpmbuild_dir)/SOURCES
	rpmbuild --nodeps -v -ba $(spec) --define "_topdir $(rpmbuild_dir)"

deb: dist
	mkdir -p $(debbuild_dir)
	cp $(distdir).tar.gz $(debbuild_dir)/$(PACKAGE)_$(VERSION).orig.tar.gz
	tar -C $(debbuild_dir) -xvzf $(distdir).tar.gz
	cp -r debian $(debbuild_dir)/$(PACKAGE)-$(VERSION)
	cd $(debbuild_dir)/$(PACKAGE)-$(VERSION); debuild -uc -us

etics: clean rpm 
	mkdir -p tgz RPMS
	cp $(distdir).tar.gz tgz
	cp -r $(rpmbuild_dir)/RPMS/* $(rpmbuild_dir)/SRPMS/* RPMS

etics-deb: clean deb
	mkdir -p tgz debs
	cp $(distdir).tar.gz tgz
	cp $(debbuild_dir)/*.deb debs
	cp $(debbuild_dir)/*.tar.gz $(debbuild_dir)/*.dsc tgz

stage-deb:
	mkdir -p $(stage_dir)
	for d in debs/*.deb; do \
		dpkg-deb --extract $$d $(stage_dir) ; \
	done
	
stage:
	mkdir -p $(stage_dir)
	
	for r in $(shell find $(rpmbuild_dir)/RPMS -name '*.rpm') ; do \
                echo "Istalling `basename $$r` in $(stage_dir)..."; \
                pushd . ; cp $$r $(stage_dir); cd $(stage_dir); \
                rpm2cpio `basename $$r` | cpio -idm; \
                rm `basename $$r`; popd; \
    done
