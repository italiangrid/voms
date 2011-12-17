ACLOCAL_AMFLAGS=-I m4
SUBDIRS = src doc m4 testsuite

EXTRA_DIST = autogen.sh LICENSE

APIDOC_DIR = $(top_builddir)/doc/apidoc
USERDOC_DIR = $(top_builddir)/doc/userdoc

APIDOC_FILES = $(top_srcdir)/AUTHORS $(top_srcdir)/INSTALL $(top_srcdir)/LICENSE $(top_srcdir)/README
USERDOC_FILES = $(APIDOC_FILES)

spec=spec/voms-all.spec
rpmbuild_dir=$(shell pwd)/rpmbuild

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
	rm -rf rpmbuild $(distdir).tar.gz

distclean-local: 
	rm -f configure aclocal.m4 $(distdir).tar.gz 
	rm -f m4/libtool.m4 m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4
	rm -rf autom4te.cache aux src/autogen rpmbuild
	find . -name Makefile.in -exec rm {} \;


rpm: dist
	mkdir -p $(rpmbuild_dir)/BUILD $(rpmbuild_dir)/RPMS $(rpmbuild_dir)/SOURCES $(rpmbuild_dir)/SPECS $(rpmbuild_dir)/SRPMS
	cp $(distdir).tar.gz $(rpmbuild_dir)/SOURCES
	rpmbuild --nodeps -v -ba $(spec) --define "_topdir $(rpmbuild_dir)"

etics: clean rpm 
	mkdir -p tgz RPMS
	cp $(distdir).tar.gz tgz
	cp -r $(rpmbuild_dir)/RPMS/* $(rpmbuild_dir)/SRPMS/* RPMS
